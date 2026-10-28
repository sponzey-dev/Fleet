//! Purpose-bound human credentials; adapters own token proof, clocks and atomic persistence.

use crate::{AdminAccount, AdminAccountStatus, AdminRevision, AdminUserId};
use std::fmt::{Debug, Display, Formatter};

/// Failures contain no token, digest or user-supplied material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminCredentialError {
    InvalidId,
    InvalidLabel,
    InvalidTime,
    InvalidSnapshot,
    PersonalModeRequired,
    WrongPurpose,
    Inactive,
    Expired,
    StaleBinding,
    AccountUnavailable,
}

impl Display for AdminCredentialError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidId => "invalid human credential identifier",
            Self::InvalidLabel => "invalid personal token label",
            Self::InvalidTime => "invalid human credential timestamp",
            Self::InvalidSnapshot => "invalid human credential snapshot",
            Self::PersonalModeRequired => "personal authentication is unavailable",
            Self::WrongPurpose => "human credential purpose mismatch",
            Self::Inactive => "human credential is no longer active",
            Self::Expired => "human credential expired",
            Self::StaleBinding => "human credential binding is stale",
            Self::AccountUnavailable => "administrator account is unavailable",
        })
    }
}

impl std::error::Error for AdminCredentialError {}

/// Credential record identifier, distinct from the secret used to locate the record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdminCredentialId(String);

impl AdminCredentialId {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, AdminCredentialError> {
        let value = value.as_ref();
        if value.len() != 36
            || !value.strip_prefix("crd_").is_some_and(|suffix| {
                suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
        {
            return Err(AdminCredentialError::InvalidId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Adapter-computed purpose-bound digest, never the raw credential.
#[derive(Clone, PartialEq, Eq)]
pub struct AdminCredentialDigest([u8; 32]);

impl AdminCredentialDigest {
    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Explicit persistence/lookup mapping only; not a constant-time authentication comparison.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Debug for AdminCredentialDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AdminCredentialDigest([REDACTED])")
    }
}

impl Display for AdminCredentialDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("credential_digest")
    }
}

/// Human-only restore generation; never substitutes for Agent delivery or signing identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HumanAuthEpoch([u8; 16]);

impl HumanAuthEpoch {
    pub fn from_bytes(value: [u8; 16]) -> Self {
        Self(value)
    }

    pub fn bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Debug for HumanAuthEpoch {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HumanAuthEpoch([REDACTED])")
    }
}

/// Legacy access is available only before explicit personal-account cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAuthMode {
    LegacyBootstrap,
    Personal,
    LocalSetupRequired,
}

impl AdminAuthMode {
    /// A restore never revives shared-token access, even for a pre-IAM backup.
    pub fn after_restore(has_loginable_owner: bool) -> Self {
        if has_loginable_owner {
            Self::Personal
        } else {
            Self::LocalSetupRequired
        }
    }
}

/// Token purpose determines both lifetime and the account state in which it can be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminCredentialKind {
    WebSession,
    PersonalToken,
    SetupGrant,
    ResetGrant,
}

impl AdminCredentialKind {
    pub fn lifetime_seconds(self) -> i64 {
        match self {
            Self::WebSession => 28_800,
            Self::PersonalToken => 2_592_000,
            Self::SetupGrant | Self::ResetGrant => 900,
        }
    }

    pub fn is_grant(self) -> bool {
        matches!(self, Self::SetupGrant | Self::ResetGrant)
    }
}

/// Revocation and grant consumption are terminal; expiry is a clock-dependent check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminCredentialState {
    Active,
    Revoked,
    Consumed,
}

/// Authentication binds to immutable subject and the current credential generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCredentialBinding {
    pub user_id: AdminUserId,
    pub credential_revision: AdminRevision,
    pub epoch: HumanAuthEpoch,
}

impl AdminCredentialBinding {
    pub fn for_account(account: &AdminAccount, epoch: HumanAuthEpoch) -> Self {
        let account = account.snapshot();
        Self {
            user_id: account.id,
            credential_revision: account.credential_revision,
            epoch,
        }
    }
}

/// Semantic repository boundary; external DTOs and persistence rows must map explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCredentialSnapshot {
    pub id: AdminCredentialId,
    pub kind: AdminCredentialKind,
    pub digest: AdminCredentialDigest,
    pub binding: AdminCredentialBinding,
    pub created_at: i64,
    pub expires_at: i64,
    pub state: AdminCredentialState,
    pub ended_at: Option<i64>,
    pub label: Option<AdminTokenLabel>,
}

/// Optional user-visible PAT name, separate from all authentication material.
#[derive(Clone, PartialEq, Eq)]
pub struct AdminTokenLabel(String);

impl AdminTokenLabel {
    pub fn parse(value: &str) -> Result<Self, AdminCredentialError> {
        if value.is_empty()
            || value.len() > 256
            || value.trim().is_empty()
            || value.chars().any(char::is_control)
        {
            return Err(AdminCredentialError::InvalidLabel);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for AdminTokenLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminTokenLabel([REDACTED])")
    }
}

/// Canonical human credential lifecycle, with no sliding renewal or token proof mechanism.
#[derive(Debug, Clone)]
pub struct AdminCredential {
    state: AdminCredentialSnapshot,
}

impl AdminCredential {
    /// Issues a fixed-lifetime record; the application owns admission and atomic persistence.
    pub fn issue(
        id: AdminCredentialId,
        kind: AdminCredentialKind,
        digest: AdminCredentialDigest,
        binding: AdminCredentialBinding,
        created_at: i64,
    ) -> Result<Self, AdminCredentialError> {
        let expires_at = created_at
            .checked_add(kind.lifetime_seconds())
            .filter(|_| created_at >= 0)
            .ok_or(AdminCredentialError::InvalidTime)?;
        Ok(Self {
            state: AdminCredentialSnapshot {
                id,
                kind,
                digest,
                binding,
                created_at,
                expires_at,
                state: AdminCredentialState::Active,
                ended_at: None,
                label: None,
            },
        })
    }

    /// Creates a PAT with its immutable optional display label. Other purposes never carry labels.
    pub fn issue_personal_token(
        id: AdminCredentialId,
        digest: AdminCredentialDigest,
        binding: AdminCredentialBinding,
        created_at: i64,
        label: Option<AdminTokenLabel>,
    ) -> Result<Self, AdminCredentialError> {
        let mut credential = Self::issue(
            id,
            AdminCredentialKind::PersonalToken,
            digest,
            binding,
            created_at,
        )?;
        credential.state.label = label;
        Ok(credential)
    }

    pub fn from_snapshot(state: AdminCredentialSnapshot) -> Result<Self, AdminCredentialError> {
        let expected_expiry = state.created_at.checked_add(state.kind.lifetime_seconds());
        let terminal_valid = match (state.state, state.ended_at) {
            (AdminCredentialState::Active, None) => true,
            (AdminCredentialState::Revoked, Some(ended)) => ended >= state.created_at,
            (AdminCredentialState::Consumed, Some(ended)) => {
                state.kind.is_grant() && ended >= state.created_at && ended < state.expires_at
            }
            _ => false,
        };
        if state.created_at < 0
            || expected_expiry != Some(state.expires_at)
            || !terminal_valid
            || (state.label.is_some() && state.kind != AdminCredentialKind::PersonalToken)
        {
            return Err(AdminCredentialError::InvalidSnapshot);
        }
        Ok(Self { state })
    }

    pub fn snapshot(&self) -> AdminCredentialSnapshot {
        self.state.clone()
    }

    /// Checks a digest-resolved trusted record against current canonical state.
    ///
    /// Successful validation does not extend expiry. Callers must repeat it at a
    /// protected write's commit boundary; a previous success is not authority.
    pub fn validate(
        &self,
        expected_kind: AdminCredentialKind,
        mode: AdminAuthMode,
        account: &AdminAccount,
        current_epoch: HumanAuthEpoch,
        now: i64,
    ) -> Result<(), AdminCredentialError> {
        if mode != AdminAuthMode::Personal {
            return Err(AdminCredentialError::PersonalModeRequired);
        }
        if self.state.kind != expected_kind {
            return Err(AdminCredentialError::WrongPurpose);
        }
        if self.state.state != AdminCredentialState::Active {
            return Err(AdminCredentialError::Inactive);
        }
        if now < self.state.created_at {
            return Err(AdminCredentialError::InvalidTime);
        }
        if now >= self.state.expires_at {
            return Err(AdminCredentialError::Expired);
        }
        let current = account.snapshot();
        if self.state.binding.user_id != current.id
            || self.state.binding.credential_revision != current.credential_revision
            || self.state.binding.epoch != current_epoch
        {
            return Err(AdminCredentialError::StaleBinding);
        }
        let usable_account = if self.state.kind.is_grant() {
            current.status == AdminAccountStatus::PendingSetup
        } else {
            account.is_loginable()
        };
        if !usable_account {
            return Err(AdminCredentialError::AccountUnavailable);
        }
        Ok(())
    }

    /// Revokes only this record; duplicate terminal operations retain their original timestamp.
    pub fn revoke(&mut self, now: i64) -> Result<bool, AdminCredentialError> {
        if now < self.state.created_at {
            return Err(AdminCredentialError::InvalidTime);
        }
        if self.state.state != AdminCredentialState::Active {
            return Ok(false);
        }
        self.state.state = AdminCredentialState::Revoked;
        self.state.ended_at = Some(now);
        Ok(true)
    }

    /// Consumes a currently valid one-time grant; persistence must commit this with its effect.
    pub fn consume(
        &mut self,
        expected_kind: AdminCredentialKind,
        mode: AdminAuthMode,
        account: &AdminAccount,
        current_epoch: HumanAuthEpoch,
        now: i64,
    ) -> Result<(), AdminCredentialError> {
        if !self.state.kind.is_grant() {
            return Err(AdminCredentialError::WrongPurpose);
        }
        self.validate(expected_kind, mode, account, current_epoch, now)?;
        self.state.state = AdminCredentialState::Consumed;
        self.state.ended_at = Some(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    fn account(active: bool) -> AdminAccount {
        let mut account = AdminAccount::pending(
            AdminUserId::parse("usr_00000000000000000000000000000001").unwrap(),
            AdminUsername::parse("fixture_user").unwrap(),
            AdminDisplayName::parse("Fixture user").unwrap(),
            AdminRole::Owner,
        );
        if active {
            account.install_password(verifier()).unwrap();
        }
        account
    }

    fn verifier() -> AdminPasswordVerifier {
        AdminPasswordVerifier::from_parts(AdminPasswordVerifier::PROFILE_ID, &[1; 16], &[2; 32])
            .unwrap()
    }

    fn issue(kind: AdminCredentialKind, account: &AdminAccount) -> AdminCredential {
        AdminCredential::issue(
            AdminCredentialId::parse("crd_00000000000000000000000000000001").unwrap(),
            kind,
            AdminCredentialDigest::from_bytes([7; 32]),
            AdminCredentialBinding::for_account(account, HumanAuthEpoch::from_bytes([9; 16])),
            1_000,
        )
        .unwrap()
    }

    fn validate(
        credential: &AdminCredential,
        account: &AdminAccount,
        now: i64,
    ) -> Result<(), AdminCredentialError> {
        credential.validate(
            credential.snapshot().kind,
            AdminAuthMode::Personal,
            account,
            HumanAuthEpoch::from_bytes([9; 16]),
            now,
        )
    }

    #[test]
    fn fixed_lifetimes_have_exact_non_sliding_boundaries() {
        for (kind, active, lifetime) in [
            (AdminCredentialKind::WebSession, true, 28_800),
            (AdminCredentialKind::PersonalToken, true, 2_592_000),
            (AdminCredentialKind::SetupGrant, false, 900),
            (AdminCredentialKind::ResetGrant, false, 900),
        ] {
            let account = account(active);
            let credential = issue(kind, &account);
            let snapshot = credential.snapshot();
            assert_eq!(snapshot.expires_at, 1_000 + lifetime);
            assert!(validate(&credential, &account, 999).is_err());
            assert!(validate(&credential, &account, 1_000).is_ok());
            assert!(validate(&credential, &account, snapshot.expires_at - 1).is_ok());
            assert_eq!(
                validate(&credential, &account, snapshot.expires_at),
                Err(AdminCredentialError::Expired)
            );
            assert_eq!(snapshot, credential.snapshot());
        }
    }

    #[test]
    fn wrong_purpose_subject_revision_epoch_and_mode_are_denied() {
        let account = account(true);
        let credential = issue(AdminCredentialKind::WebSession, &account);
        let epoch = HumanAuthEpoch::from_bytes([9; 16]);
        assert_eq!(
            credential.validate(
                AdminCredentialKind::PersonalToken,
                AdminAuthMode::Personal,
                &account,
                epoch,
                1_001
            ),
            Err(AdminCredentialError::WrongPurpose)
        );
        for mode in [
            AdminAuthMode::LegacyBootstrap,
            AdminAuthMode::LocalSetupRequired,
        ] {
            assert_eq!(
                credential.validate(
                    AdminCredentialKind::WebSession,
                    mode,
                    &account,
                    epoch,
                    1_001
                ),
                Err(AdminCredentialError::PersonalModeRequired)
            );
        }
        assert_eq!(
            credential.validate(
                AdminCredentialKind::WebSession,
                AdminAuthMode::Personal,
                &account,
                HumanAuthEpoch::from_bytes([8; 16]),
                1_001
            ),
            Err(AdminCredentialError::StaleBinding)
        );
        let mut changed = account.snapshot();
        changed.id = AdminUserId::parse("usr_00000000000000000000000000000002").unwrap();
        assert_eq!(
            validate(
                &credential,
                &AdminAccount::from_snapshot(changed).unwrap(),
                1_001
            ),
            Err(AdminCredentialError::StaleBinding)
        );
        let mut changed = account.clone();
        changed.change_role(AdminRole::Admin, 1).unwrap();
        assert_eq!(
            validate(&credential, &changed, 1_001),
            Err(AdminCredentialError::StaleBinding)
        );
        let mut changed = account.clone();
        changed
            .rename(AdminDisplayName::parse("Renamed user").unwrap())
            .unwrap();
        assert!(validate(&credential, &changed, 1_001).is_ok());
    }

    #[test]
    fn account_status_is_checked_independently_of_matching_binding() {
        let pending = account(false);
        assert_eq!(
            validate(
                &issue(AdminCredentialKind::WebSession, &pending),
                &pending,
                1_000
            ),
            Err(AdminCredentialError::AccountUnavailable)
        );
        let mut active = account(true);
        assert_eq!(
            validate(
                &issue(AdminCredentialKind::ResetGrant, &active),
                &active,
                1_000
            ),
            Err(AdminCredentialError::AccountUnavailable)
        );
        active.disable(1).unwrap();
        for kind in [
            AdminCredentialKind::WebSession,
            AdminCredentialKind::PersonalToken,
            AdminCredentialKind::SetupGrant,
            AdminCredentialKind::ResetGrant,
        ] {
            assert_eq!(
                validate(&issue(kind, &active), &active, 1_000),
                Err(AdminCredentialError::AccountUnavailable)
            );
        }
    }

    #[test]
    fn grants_are_single_use_and_other_credentials_cannot_be_consumed() {
        for kind in [
            AdminCredentialKind::SetupGrant,
            AdminCredentialKind::ResetGrant,
        ] {
            let account = account(false);
            let mut grant = issue(kind, &account);
            grant
                .consume(
                    kind,
                    AdminAuthMode::Personal,
                    &account,
                    HumanAuthEpoch::from_bytes([9; 16]),
                    1_001,
                )
                .unwrap();
            assert_eq!(grant.snapshot().state, AdminCredentialState::Consumed);
            assert_eq!(grant.snapshot().ended_at, Some(1_001));
            assert_eq!(
                validate(&grant, &account, 1_002),
                Err(AdminCredentialError::Inactive)
            );
            assert!(
                grant
                    .consume(
                        kind,
                        AdminAuthMode::Personal,
                        &account,
                        HumanAuthEpoch::from_bytes([9; 16]),
                        1_002
                    )
                    .is_err()
            );
            assert!(!grant.revoke(1_003).unwrap());
            assert_eq!(grant.snapshot().ended_at, Some(1_001));
        }
        let account = account(true);
        let mut session = issue(AdminCredentialKind::WebSession, &account);
        let before = session.snapshot();
        assert_eq!(
            session.consume(
                AdminCredentialKind::WebSession,
                AdminAuthMode::Personal,
                &account,
                HumanAuthEpoch::from_bytes([9; 16]),
                1_001
            ),
            Err(AdminCredentialError::WrongPurpose)
        );
        assert_eq!(before, session.snapshot());
    }

    #[test]
    fn individual_revoke_preserves_terminal_state_without_revoking_a_sibling() {
        let account = account(true);
        let mut first = issue(AdminCredentialKind::PersonalToken, &account);
        let second = issue(AdminCredentialKind::PersonalToken, &account);
        assert_eq!(first.revoke(999), Err(AdminCredentialError::InvalidTime));
        assert!(validate(&first, &account, 1_000).is_ok());
        assert!(first.revoke(1_001).unwrap());
        assert!(!first.revoke(1_002).unwrap());
        assert_eq!(first.snapshot().ended_at, Some(1_001));
        assert_eq!(
            validate(&first, &account, 1_002),
            Err(AdminCredentialError::Inactive)
        );
        assert!(validate(&second, &account, 1_002).is_ok());
    }

    #[test]
    fn invalid_snapshots_times_and_overflow_are_rejected() {
        let active = account(true);
        let original = issue(AdminCredentialKind::WebSession, &active).snapshot();
        for invalid in [
            {
                let mut s = original.clone();
                s.expires_at += 1;
                s
            },
            {
                let mut s = original.clone();
                s.created_at = -1;
                s
            },
            {
                let mut s = original.clone();
                s.ended_at = Some(1_001);
                s
            },
            {
                let mut s = original.clone();
                s.state = AdminCredentialState::Revoked;
                s
            },
            {
                let mut s = original.clone();
                s.state = AdminCredentialState::Revoked;
                s.ended_at = Some(999);
                s
            },
            {
                let mut s = original.clone();
                s.state = AdminCredentialState::Consumed;
                s.ended_at = Some(1_001);
                s
            },
        ] {
            assert!(AdminCredential::from_snapshot(invalid).is_err());
        }
        for invalid_time in [-1, i64::MAX] {
            assert!(
                AdminCredential::issue(
                    original.id.clone(),
                    original.kind,
                    original.digest.clone(),
                    original.binding.clone(),
                    invalid_time
                )
                .is_err()
            );
        }
        let mut grant = issue(AdminCredentialKind::SetupGrant, &account(false)).snapshot();
        grant.state = AdminCredentialState::Consumed;
        grant.ended_at = Some(grant.expires_at);
        assert!(AdminCredential::from_snapshot(grant).is_err());
        assert!(AdminCredential::from_snapshot(original).is_ok());
    }

    #[test]
    fn credential_namespaces_and_secret_formatting_are_safe() {
        for invalid in [
            "usr_00000000000000000000000000000001",
            "crd_0000000000000000000000000000000A",
            "crd_1",
        ] {
            assert!(AdminCredentialId::parse(invalid).is_err());
        }
        let digest = AdminCredentialDigest::from_bytes([0xab; 32]);
        assert_eq!(digest.bytes(), &[0xab; 32]);
        assert_eq!(format!("{digest:?}"), "AdminCredentialDigest([REDACTED])");
        assert_eq!(format!("{digest}"), "credential_digest");
        let epoch = HumanAuthEpoch::from_bytes([9; 16]);
        assert_eq!(epoch.bytes(), &[9; 16]);
        assert_ne!(epoch, HumanAuthEpoch::from_bytes([8; 16]));
    }

    #[test]
    fn restored_auth_never_reenables_a_legacy_shared_token() {
        assert_eq!(AdminAuthMode::after_restore(true), AdminAuthMode::Personal);
        assert_eq!(
            AdminAuthMode::after_restore(false),
            AdminAuthMode::LocalSetupRequired
        );
    }

    #[test]
    fn personal_token_labels_are_bounded_nonblank_text_and_redacted_in_diagnostics() {
        let label = AdminTokenLabel::parse(" My laptop CLI ").unwrap();
        assert_eq!(label.as_str(), " My laptop CLI ");
        assert!(!format!("{label:?}").contains("My laptop CLI"));
        assert!(AdminTokenLabel::parse(&"x".repeat(256)).is_ok());
        assert!(AdminTokenLabel::parse(&"가".repeat(85)).is_ok());
        for invalid in [
            String::new(),
            "   ".into(),
            "synthetic-secret\n".into(),
            "x".repeat(257),
            "가".repeat(86),
        ] {
            let error = AdminTokenLabel::parse(&invalid).unwrap_err();
            assert_eq!(error, AdminCredentialError::InvalidLabel);
            assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
        }
    }

    #[test]
    fn only_personal_token_snapshots_can_own_a_label() {
        let account = account(true);
        let existing = issue(AdminCredentialKind::PersonalToken, &account).snapshot();
        let label = AdminTokenLabel::parse("My CLI").unwrap();
        let token = AdminCredential::issue_personal_token(
            existing.id,
            existing.digest,
            existing.binding,
            1_000,
            Some(label.clone()),
        )
        .unwrap();
        assert_eq!(token.snapshot().expires_at, 2_593_000);
        assert_eq!(token.snapshot().label, Some(label.clone()));
        assert!(AdminCredential::from_snapshot(token.snapshot()).is_ok());
        for kind in [
            AdminCredentialKind::WebSession,
            AdminCredentialKind::SetupGrant,
            AdminCredentialKind::ResetGrant,
        ] {
            let mut snapshot = issue(kind, &account).snapshot();
            snapshot.label = Some(label.clone());
            assert!(matches!(
                AdminCredential::from_snapshot(snapshot),
                Err(AdminCredentialError::InvalidSnapshot)
            ));
        }
    }
}
