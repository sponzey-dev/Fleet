//! Administrator account transitions; callers provide authorization and transactional owner counts.

use crate::{AdminDisplayName, AdminPasswordVerifier, AdminRole, AdminUserId, AdminUsername};
use std::fmt::{Display, Formatter};

/// Account transition failures never include credential or caller-provided text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAccountError {
    InvalidRevision,
    InvalidSnapshot,
    LastOwner,
    DisabledAccount,
    RevisionExhausted,
}

impl Display for AdminAccountError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRevision => "invalid administrator revision",
            Self::InvalidSnapshot => "invalid administrator account snapshot",
            Self::LastOwner => "the last active owner must remain available",
            Self::DisabledAccount => "disabled administrator requires reset or local recovery",
            Self::RevisionExhausted => "administrator revision exhausted",
        })
    }
}

impl std::error::Error for AdminAccountError {}

/// A nonnegative, monotonic account sequence with checked exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdminRevision(i64);

impl AdminRevision {
    pub const INITIAL: Self = Self(0);

    pub fn new(value: i64) -> Result<Self, AdminAccountError> {
        if value < 0 {
            return Err(AdminAccountError::InvalidRevision);
        }
        Ok(Self(value))
    }

    pub fn value(self) -> i64 {
        self.0
    }

    fn next(self) -> Result<Self, AdminAccountError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(AdminAccountError::RevisionExhausted)
    }
}

/// Setup requires a one-time claim; disabled accounts cannot install a password remotely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAccountStatus {
    PendingSetup,
    Active,
    Disabled,
}

/// Semantic state for repository conversion, not an HTTP or persistence record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAccountSnapshot {
    pub id: AdminUserId,
    pub username: AdminUsername,
    pub display_name: AdminDisplayName,
    pub role: AdminRole,
    pub status: AdminAccountStatus,
    pub record_revision: AdminRevision,
    pub credential_revision: AdminRevision,
    pub password_verifier: Option<AdminPasswordVerifier>,
}

/// Describes what the application must persist and invalidate atomically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAccountChange {
    Unchanged,
    MetadataChanged,
    CredentialsChanged,
}

/// Canonical account state, independent of database, actor lookup, clock and crypto execution.
#[derive(Debug, Clone)]
pub struct AdminAccount {
    state: AdminAccountSnapshot,
}

impl AdminAccount {
    pub fn pending(
        id: AdminUserId,
        username: AdminUsername,
        display_name: AdminDisplayName,
        role: AdminRole,
    ) -> Self {
        Self {
            state: AdminAccountSnapshot {
                id,
                username,
                display_name,
                role,
                status: AdminAccountStatus::PendingSetup,
                record_revision: AdminRevision::INITIAL,
                credential_revision: AdminRevision::INITIAL,
                password_verifier: None,
            },
        }
    }

    /// Rejects restored states whose status, verifier or sequence history is inconsistent.
    pub fn from_snapshot(state: AdminAccountSnapshot) -> Result<Self, AdminAccountError> {
        if state.credential_revision > state.record_revision
            || (state.status == AdminAccountStatus::Active && state.password_verifier.is_none())
            || (state.status == AdminAccountStatus::PendingSetup
                && state.password_verifier.is_some())
        {
            return Err(AdminAccountError::InvalidSnapshot);
        }
        Ok(Self { state })
    }

    pub fn snapshot(&self) -> AdminAccountSnapshot {
        self.state.clone()
    }

    pub fn is_loginable(&self) -> bool {
        self.state.status == AdminAccountStatus::Active && self.state.password_verifier.is_some()
    }

    /// Changes display metadata without revoking otherwise valid credentials.
    pub fn rename(
        &mut self,
        display_name: AdminDisplayName,
    ) -> Result<AdminAccountChange, AdminAccountError> {
        if self.state.display_name == display_name {
            return Ok(AdminAccountChange::Unchanged);
        }
        let next = self.state.record_revision.next()?;
        self.state.display_name = display_name;
        self.state.record_revision = next;
        Ok(AdminAccountChange::MetadataChanged)
    }

    /// Applies a verified password or setup claim; caller owns proof and authorization checks.
    pub fn install_password(
        &mut self,
        verifier: AdminPasswordVerifier,
    ) -> Result<AdminAccountChange, AdminAccountError> {
        if self.state.status == AdminAccountStatus::Disabled {
            return Err(AdminAccountError::DisabledAccount);
        }
        let (record, credential) = self.next_credential_revisions()?;
        self.state.password_verifier = Some(verifier);
        self.state.status = AdminAccountStatus::Active;
        self.set_revisions(record, credential);
        Ok(AdminAccountChange::CredentialsChanged)
    }

    /// Owner count must be read and the effect committed within the same application transaction.
    pub fn change_role(
        &mut self,
        role: AdminRole,
        other_loginable_owners: usize,
    ) -> Result<AdminAccountChange, AdminAccountError> {
        if role == self.state.role {
            return Ok(AdminAccountChange::Unchanged);
        }
        if role != AdminRole::Owner {
            self.ensure_owner_can_be_removed(other_loginable_owners)?;
        }
        let (record, credential) = self.next_credential_revisions()?;
        self.state.role = role;
        self.set_revisions(record, credential);
        Ok(AdminAccountChange::CredentialsChanged)
    }

    /// A duplicate disable has no new revocation or sequence effect.
    pub fn disable(
        &mut self,
        other_loginable_owners: usize,
    ) -> Result<AdminAccountChange, AdminAccountError> {
        if self.state.status == AdminAccountStatus::Disabled {
            return Ok(AdminAccountChange::Unchanged);
        }
        self.ensure_owner_can_be_removed(other_loginable_owners)?;
        let (record, credential) = self.next_credential_revisions()?;
        self.state.status = AdminAccountStatus::Disabled;
        self.set_revisions(record, credential);
        Ok(AdminAccountChange::CredentialsChanged)
    }

    /// Invalidates prior credentials and codes before a new setup grant is issued.
    pub fn begin_password_reset(
        &mut self,
        other_loginable_owners: usize,
    ) -> Result<AdminAccountChange, AdminAccountError> {
        self.ensure_owner_can_be_removed(other_loginable_owners)?;
        let (record, credential) = self.next_credential_revisions()?;
        self.state.status = AdminAccountStatus::PendingSetup;
        self.state.password_verifier = None;
        self.set_revisions(record, credential);
        Ok(AdminAccountChange::CredentialsChanged)
    }

    /// Local recovery effect only; the application must hold verified exclusive OS authority.
    pub fn recover_owner(
        &mut self,
        verifier: AdminPasswordVerifier,
    ) -> Result<AdminAccountChange, AdminAccountError> {
        let (record, credential) = self.next_credential_revisions()?;
        self.state.role = AdminRole::Owner;
        self.state.status = AdminAccountStatus::Active;
        self.state.password_verifier = Some(verifier);
        self.set_revisions(record, credential);
        Ok(AdminAccountChange::CredentialsChanged)
    }

    fn ensure_owner_can_be_removed(&self, other_owners: usize) -> Result<(), AdminAccountError> {
        if self.state.role == AdminRole::Owner && self.is_loginable() && other_owners == 0 {
            return Err(AdminAccountError::LastOwner);
        }
        Ok(())
    }

    fn next_credential_revisions(
        &self,
    ) -> Result<(AdminRevision, AdminRevision), AdminAccountError> {
        Ok((
            self.state.record_revision.next()?,
            self.state.credential_revision.next()?,
        ))
    }

    fn set_revisions(&mut self, record: AdminRevision, credential: AdminRevision) {
        self.state.record_revision = record;
        self.state.credential_revision = credential;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdminDisplayName, AdminPasswordVerifier, AdminRole, AdminUserId, AdminUsername};

    fn verifier(value: u8) -> AdminPasswordVerifier {
        AdminPasswordVerifier::from_parts(
            AdminPasswordVerifier::PROFILE_ID,
            &[value; 16],
            &[value; 32],
        )
        .unwrap()
    }

    fn pending(role: AdminRole) -> AdminAccount {
        AdminAccount::pending(
            AdminUserId::parse("usr_00000000000000000000000000000001").unwrap(),
            AdminUsername::parse("fixture_user").unwrap(),
            AdminDisplayName::parse("Fixture operator").unwrap(),
            role,
        )
    }

    fn active(role: AdminRole) -> AdminAccount {
        let mut account = pending(role);
        assert_eq!(
            account.install_password(verifier(1)).unwrap(),
            AdminAccountChange::CredentialsChanged
        );
        account
    }

    #[test]
    fn setup_activation_and_metadata_changes_preserve_identity_and_credentials() {
        let mut account = pending(AdminRole::Viewer);
        assert_eq!(account.snapshot().status, AdminAccountStatus::PendingSetup);
        assert!(!account.is_loginable());
        let identity = account.snapshot();
        account.install_password(verifier(1)).unwrap();
        assert!(account.is_loginable());
        let before = account.snapshot();
        assert_eq!(
            account
                .rename(AdminDisplayName::parse("Updated fixture name").unwrap())
                .unwrap(),
            AdminAccountChange::MetadataChanged
        );
        let after = account.snapshot();
        assert_eq!(after.id, identity.id);
        assert_eq!(after.username, identity.username);
        assert_eq!(after.credential_revision, before.credential_revision);
        assert_eq!(
            after.record_revision.value(),
            before.record_revision.value() + 1
        );
        assert_eq!(after.password_verifier, before.password_verifier);
    }

    #[test]
    fn last_loginable_owner_cannot_be_disabled_demoted_or_reset() {
        let mut account = active(AdminRole::Owner);
        let before = account.snapshot();
        assert_eq!(account.disable(0), Err(AdminAccountError::LastOwner));
        assert_eq!(account.snapshot(), before);
        assert_eq!(
            account.change_role(AdminRole::Admin, 0),
            Err(AdminAccountError::LastOwner)
        );
        assert_eq!(account.snapshot(), before);
        assert_eq!(
            account.begin_password_reset(0),
            Err(AdminAccountError::LastOwner)
        );
        assert_eq!(account.snapshot(), before);
        assert_eq!(
            account.change_role(AdminRole::Admin, 1).unwrap(),
            AdminAccountChange::CredentialsChanged
        );
        assert!(account.is_loginable());
    }

    #[test]
    fn duplicate_metadata_role_and_disable_do_not_advance_revisions() {
        let mut account = active(AdminRole::Operator);
        let before = account.snapshot();
        assert_eq!(
            account.change_role(AdminRole::Operator, 0).unwrap(),
            AdminAccountChange::Unchanged
        );
        assert_eq!(
            account.rename(before.display_name.clone()).unwrap(),
            AdminAccountChange::Unchanged
        );
        assert_eq!(account.snapshot(), before);
        account.disable(0).unwrap();
        let disabled = account.snapshot();
        assert_eq!(account.disable(0).unwrap(), AdminAccountChange::Unchanged);
        assert_eq!(account.snapshot(), disabled);
    }

    #[test]
    fn disabled_accounts_require_reset_before_remote_password_installation() {
        let mut account = active(AdminRole::Viewer);
        let before = account.snapshot();
        account.disable(0).unwrap();
        assert!(!account.is_loginable());
        assert!(account.snapshot().credential_revision > before.credential_revision);
        let disabled = account.snapshot();
        assert_eq!(
            account.install_password(verifier(2)),
            Err(AdminAccountError::DisabledAccount)
        );
        assert_eq!(account.snapshot(), disabled);
        account.begin_password_reset(0).unwrap();
        assert_eq!(account.snapshot().status, AdminAccountStatus::PendingSetup);
        assert!(account.snapshot().password_verifier.is_none());
        account.install_password(verifier(2)).unwrap();
        assert!(account.is_loginable());
        assert_eq!(account.snapshot().id, before.id);
    }

    #[test]
    fn local_recovery_restores_an_owner_and_advances_credential_revision() {
        let mut account = pending(AdminRole::Viewer);
        account.disable(0).unwrap();
        let before = account.snapshot();
        assert_eq!(
            account.recover_owner(verifier(3)).unwrap(),
            AdminAccountChange::CredentialsChanged
        );
        let after = account.snapshot();
        assert!(account.is_loginable());
        assert_eq!(after.role, AdminRole::Owner);
        assert!(after.credential_revision > before.credential_revision);
        assert_eq!(after.id, before.id);
        assert_eq!(after.username, before.username);
    }

    #[test]
    fn invalid_restored_shapes_and_negative_revisions_are_rejected() {
        assert_eq!(
            AdminRevision::new(-1),
            Err(AdminAccountError::InvalidRevision)
        );
        let mut snapshot = active(AdminRole::Viewer).snapshot();
        snapshot.password_verifier = None;
        assert!(matches!(
            AdminAccount::from_snapshot(snapshot),
            Err(AdminAccountError::InvalidSnapshot)
        ));
        let mut snapshot = pending(AdminRole::Viewer).snapshot();
        snapshot.password_verifier = Some(verifier(1));
        assert!(AdminAccount::from_snapshot(snapshot).is_err());
        let mut snapshot = active(AdminRole::Viewer).snapshot();
        snapshot.credential_revision =
            AdminRevision::new(snapshot.record_revision.value() + 1).unwrap();
        assert!(AdminAccount::from_snapshot(snapshot).is_err());
    }

    #[test]
    fn revision_exhaustion_preserves_all_account_state() {
        let mut snapshot = active(AdminRole::Owner).snapshot();
        snapshot.record_revision = AdminRevision::new(i64::MAX).unwrap();
        snapshot.credential_revision = AdminRevision::new(i64::MAX).unwrap();
        let mut account = AdminAccount::from_snapshot(snapshot).unwrap();
        let before = account.snapshot();
        assert_eq!(
            account.rename(AdminDisplayName::parse("Different name").unwrap()),
            Err(AdminAccountError::RevisionExhausted)
        );
        assert_eq!(account.snapshot(), before);
        assert_eq!(
            account.change_role(AdminRole::Admin, 1),
            Err(AdminAccountError::RevisionExhausted)
        );
        assert_eq!(account.snapshot(), before);
    }
}
