//! Pure administrator identity values and operation policy.
//! Adapters supply canonical input and perform credential lookup and cryptography.

use std::fmt::{Debug, Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A person's role grants operation permissions; it does not prove authentication.
pub enum AdminRole {
    Owner,
    Admin,
    Operator,
    Viewer,
}

impl AdminRole {
    /// Accepts only the exact, lower-case role labels used by persisted identities.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "operator" => Some(Self::Operator),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    /// Checks operation permission only; account state and subject ownership remain application guards.
    pub fn allows(self, permission: AdminPermission) -> bool {
        match permission {
            AdminPermission::AccountManage => self == Self::Owner,
            AdminPermission::SelfCredentialManage
            | AdminPermission::AgentRead
            | AdminPermission::ApprovalRead
            | AdminPermission::JobRead
            | AdminPermission::AuditRead
            | AdminPermission::PolicyRead => true,
            AdminPermission::JobCreate
            | AdminPermission::JobApprove
            | AdminPermission::JobCancel => {
                matches!(self, Self::Owner | Self::Admin | Self::Operator)
            }
            AdminPermission::AgentWrite
            | AdminPermission::AgentRevoke
            | AdminPermission::EnrollmentTokenRead
            | AdminPermission::EnrollmentTokenCreate
            | AdminPermission::EnrollmentTokenRevoke
            | AdminPermission::PolicyWrite
            | AdminPermission::SigningRotationWrite => {
                matches!(self, Self::Owner | Self::Admin)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Administrator operations with stable, intentional permission identifiers.
pub enum AdminPermission {
    AgentRead,
    AgentWrite,
    AgentRevoke,
    ApprovalRead,
    JobRead,
    JobCreate,
    JobApprove,
    JobCancel,
    EnrollmentTokenRead,
    EnrollmentTokenCreate,
    EnrollmentTokenRevoke,
    AuditRead,
    PolicyRead,
    PolicyWrite,
    SigningRotationWrite,
    AccountManage,
    SelfCredentialManage,
}

impl AdminPermission {
    /// Stable identifiers mapped by external adapters, without a transport dependency.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentRead => "agent_read",
            Self::AgentWrite => "agent_write",
            Self::AgentRevoke => "agent_revoke",
            Self::ApprovalRead => "approval_read",
            Self::JobRead => "job_read",
            Self::JobCreate => "job_create",
            Self::JobApprove => "job_approve",
            Self::JobCancel => "job_cancel",
            Self::EnrollmentTokenRead => "enrollment_token_read",
            Self::EnrollmentTokenCreate => "enrollment_token_create",
            Self::EnrollmentTokenRevoke => "enrollment_token_revoke",
            Self::AuditRead => "audit_read",
            Self::PolicyRead => "policy_read",
            Self::PolicyWrite => "policy_write",
            Self::SigningRotationWrite => "signing_rotation_write",
            Self::AccountManage => "account_manage",
            Self::SelfCredentialManage => "self_credential_manage",
        }
    }
}

/// Validation failures contain no caller-supplied identity or secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminIdentityError {
    InvalidUserId,
    InvalidUsername,
    InvalidDisplayName,
    InvalidNewPassword,
    UnsupportedPasswordProfile,
    InvalidPasswordVerifier,
}

impl Display for AdminIdentityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUserId => "invalid administrator identifier",
            Self::InvalidUsername => "invalid administrator username",
            Self::InvalidDisplayName => "invalid administrator display name",
            Self::InvalidNewPassword => "invalid administrator password input",
            Self::UnsupportedPasswordProfile => "unsupported administrator password profile",
            Self::InvalidPasswordVerifier => "invalid administrator password verifier",
        })
    }
}

impl std::error::Error for AdminIdentityError {}

/// Immutable person identifier, separate from login names and retained legacy actors.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdminUserId(String);

impl AdminUserId {
    /// Requires the person namespace and exactly 128 bits of lower-case hexadecimal.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, AdminIdentityError> {
        let value = value.as_ref();
        if value.len() != 36
            || !value.strip_prefix("usr_").is_some_and(|suffix| {
                suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
        {
            return Err(AdminIdentityError::InvalidUserId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical case-insensitive login name; whitespace and path syntax are rejected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdminUsername(String);

impl AdminUsername {
    /// Validates ASCII syntax before case folding; never trims a login name.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, AdminIdentityError> {
        let value = value.as_ref();
        if !(3..=64).contains(&value.len())
            || !value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(AdminIdentityError::InvalidUsername);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded display metadata that never serves as an authorization identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminDisplayName(String);

impl AdminDisplayName {
    /// Rejects blank/control input and counts Unicode code points rather than bytes.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, AdminIdentityError> {
        let value = value.as_ref();
        if value.len() > 480
            || value.trim().is_empty()
            || value.chars().count() > 120
            || value.chars().any(char::is_control)
        {
            return Err(AdminIdentityError::InvalidDisplayName);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Borrowed new-password syntax after adapter-owned NFC normalization.
///
/// This checks bounded length and controls only. Contextual weak-password policy
/// must also pass before hashing; it is not a credential or authentication proof.
pub struct NewAdminPassword<'a>(&'a str);

impl<'a> NewAdminPassword<'a> {
    /// Checks canonical input syntax; normalization and contextual blocklists are separate guards.
    pub fn parse(value: &'a str) -> Result<Self, AdminIdentityError> {
        if value.len() > 512
            || !(15..=128).contains(&value.chars().count())
            || value.chars().any(char::is_control)
        {
            return Err(AdminIdentityError::InvalidNewPassword);
        }
        Ok(Self(value))
    }

    /// Exposes borrowed text only for the crypto adapter, never for persistence or logs.
    pub fn expose_for_hashing(&self) -> &'a str {
        self.0
    }
}

impl Debug for NewAdminPassword<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NewAdminPassword([REDACTED])")
    }
}

impl Display for NewAdminPassword<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("admin_password")
    }
}

/// Fixed-profile verifier data, without PHC codec or hash execution in Domain.
#[derive(Clone, PartialEq, Eq)]
pub struct AdminPasswordVerifier {
    salt: [u8; 16],
    hash: [u8; 32],
}

impl AdminPasswordVerifier {
    /// Profile changes require an explicit supported-data migration decision.
    pub const PROFILE_ID: &'static str = "argon2id-v19-m19456-t2-p1";

    /// Accepts only the selected cost profile and exact public component sizes.
    /// Persistence/crypto adapters own encoding and must not expose these bytes.
    pub fn from_parts(profile: &str, salt: &[u8], hash: &[u8]) -> Result<Self, AdminIdentityError> {
        if profile != Self::PROFILE_ID {
            return Err(AdminIdentityError::UnsupportedPasswordProfile);
        }
        let salt = salt
            .try_into()
            .map_err(|_| AdminIdentityError::InvalidPasswordVerifier)?;
        let hash = hash
            .try_into()
            .map_err(|_| AdminIdentityError::InvalidPasswordVerifier)?;
        Ok(Self { salt, hash })
    }

    /// For explicit crypto/persistence mapping; never use in logs or API responses.
    pub fn salt_bytes(&self) -> &[u8; 16] {
        &self.salt
    }

    /// For explicit crypto/persistence mapping; password checking belongs to its adapter.
    pub fn hash_bytes(&self) -> &[u8; 32] {
        &self.hash
    }
}

impl Debug for AdminPasswordVerifier {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AdminPasswordVerifier([REDACTED])")
    }
}

impl Display for AdminPasswordVerifier {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("password_verifier")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AdminDisplayName, AdminPasswordVerifier, AdminPermission, AdminRole, AdminUserId,
        AdminUsername, NewAdminPassword,
    };

    #[test]
    fn only_owner_can_manage_other_accounts() {
        assert!(AdminRole::Owner.allows(AdminPermission::AccountManage));
        for role in [AdminRole::Admin, AdminRole::Operator, AdminRole::Viewer] {
            assert!(!role.allows(AdminPermission::AccountManage), "{role:?}");
        }
    }

    #[test]
    fn every_role_can_manage_its_own_credentials_subject_to_account_guards() {
        for role in [
            AdminRole::Owner,
            AdminRole::Admin,
            AdminRole::Operator,
            AdminRole::Viewer,
        ] {
            assert!(
                role.allows(AdminPermission::SelfCredentialManage),
                "{role:?}"
            );
        }
    }

    #[test]
    fn role_labels_are_exact_and_unknown_roles_do_not_gain_permissions() {
        for (label, expected) in [
            ("owner", AdminRole::Owner),
            ("admin", AdminRole::Admin),
            ("operator", AdminRole::Operator),
            ("viewer", AdminRole::Viewer),
        ] {
            assert_eq!(AdminRole::parse(label), Some(expected));
        }
        for invalid in ["", "Owner", " admin", "viewer ", "superuser", "\nowner"] {
            assert_eq!(AdminRole::parse(invalid), None);
        }
    }

    #[test]
    fn identity_values_validate_scope_and_preserve_immutable_ids() {
        let id = AdminUserId::parse("usr_0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(id.as_str(), "usr_0123456789abcdef0123456789abcdef");
        for invalid in [
            "",
            "bootstrap-admin",
            "usr_0123456789abcdef0123456789abcde",
            "usr_0123456789abcdef0123456789abcdef0",
            "usr_0123456789abcdef0123456789abcdeF",
            "usr_../../controller_private.key",
        ] {
            assert!(AdminUserId::parse(invalid).is_err());
        }
        let username = AdminUsername::parse("Fixture_User.42").unwrap();
        assert_eq!(username.as_str(), "fixture_user.42");
        assert!(AdminUsername::parse("a".repeat(64)).is_ok());
        for invalid in [
            "",
            "ab",
            "_owner",
            ".owner",
            " owner",
            "owner ",
            "owner/../x",
            "운영자",
            "owner\n",
        ] {
            assert!(AdminUsername::parse(invalid).is_err());
        }
        assert!(AdminUsername::parse("a".repeat(65)).is_err());
    }

    #[test]
    fn display_names_have_unicode_character_and_control_boundaries() {
        let name = AdminDisplayName::parse("운영 담당자 💼").unwrap();
        assert_eq!(name.as_str(), "운영 담당자 💼");
        assert!(AdminDisplayName::parse("가".repeat(120)).is_ok());
        assert!(AdminDisplayName::parse("가".repeat(121)).is_err());
        for invalid in ["", "   ", "bad\nname", "bad\0name"] {
            assert!(AdminDisplayName::parse(invalid).is_err());
        }
    }

    #[test]
    fn normalized_new_passwords_are_bounded_and_never_formatted_as_plaintext() {
        let fixture = "only an isolated password fixture";
        let password = NewAdminPassword::parse(fixture).unwrap();
        assert_eq!(password.expose_for_hashing(), fixture);
        assert_eq!(password.to_string(), "admin_password");
        assert!(!format!("{password:?}").contains(fixture));
        for count in [15, 128] {
            let text = "가".repeat(count);
            assert!(NewAdminPassword::parse(&text).is_ok());
        }
        for count in [0, 14, 129] {
            let text = "가".repeat(count);
            assert!(NewAdminPassword::parse(&text).is_err());
        }
        assert!(NewAdminPassword::parse("fixture password\nsuffix").is_err());
        assert!(NewAdminPassword::parse(&"a".repeat(2049)).is_err());
    }

    #[test]
    fn password_verifier_parts_accept_only_the_bounded_profile_and_redact_bytes() {
        let salt = [0xa7; 16];
        let hash = [0xb9; 32];
        let verifier =
            AdminPasswordVerifier::from_parts(AdminPasswordVerifier::PROFILE_ID, &salt, &hash)
                .unwrap();
        assert_eq!(verifier.salt_bytes(), &salt);
        assert_eq!(verifier.hash_bytes(), &hash);
        assert_eq!(verifier.to_string(), "password_verifier");
        assert_eq!(format!("{verifier:?}"), "AdminPasswordVerifier([REDACTED])");
        assert!(AdminPasswordVerifier::from_parts("unsupported", &salt, &hash).is_err());
        assert!(
            AdminPasswordVerifier::from_parts(AdminPasswordVerifier::PROFILE_ID, &[0; 15], &hash)
                .is_err()
        );
        assert!(
            AdminPasswordVerifier::from_parts(AdminPasswordVerifier::PROFILE_ID, &salt, &[0; 33])
                .is_err()
        );
    }
}
