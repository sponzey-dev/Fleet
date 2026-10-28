//! Fixed-profile human credential cryptography; no storage, HTTP authority or runtime configuration lookup.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use fleet_application::admin_identity::{
    AdminAccessError, AdminIdentityGenerator, AdminNewCredential, AdminSecret,
    HumanAuthEpochGenerator,
};
use fleet_domain::{
    AdminCredentialDigest, AdminCredentialId, AdminCredentialKind, AdminPasswordVerifier,
    AdminUserId, AdminUsername, HumanAuthEpoch, NewAdminPassword,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

type RandomFill = fn(&mut [u8]) -> Result<(), AdminAccessError>;

/// Bootstrap-only authentication resource settings; password cost and queue size are fixed.
#[derive(Debug, Clone, Copy)]
pub struct AdminAuthSettings {
    worker_count: usize,
}

impl AdminAuthSettings {
    pub fn new(worker_count: usize) -> Result<Self, AdminAccessError> {
        if !(1..=2).contains(&worker_count) {
            return Err(AdminAccessError::InvalidRequest);
        }
        Ok(Self { worker_count })
    }

    pub fn worker_count(self) -> usize {
        self.worker_count
    }
    pub fn pending_capacity(self) -> usize {
        1
    }
    pub fn auth_timeout(self) -> Duration {
        Duration::from_secs(30)
    }
}

/// Blocking fixed-profile primitives. Production composition must use bounded
/// worker admission off the async executor and hold no database lock while calling these.
pub(crate) struct AdminPasswordPrimitives {
    random: RandomFill,
}

impl AdminPasswordPrimitives {
    pub(crate) fn system() -> Self {
        Self {
            random: system_random,
        }
    }

    /// Normalizes and validates a new password before allocating a salt or KDF scratch memory.
    pub(crate) fn hash_new(
        &self,
        input: &str,
        username: &AdminUsername,
    ) -> Result<AdminPasswordVerifier, AdminAccessError> {
        let normalized = normalize(input)?;
        NewAdminPassword::parse(&normalized).map_err(|_| AdminAccessError::InvalidRequest)?;
        if weak_password(&normalized, username) {
            return Err(AdminAccessError::InvalidRequest);
        }
        let mut salt = [0; 16];
        (self.random)(&mut salt)?;
        let output = derive_password(&normalized, &salt)?;
        AdminPasswordVerifier::from_parts(AdminPasswordVerifier::PROFILE_ID, &salt, &output[..])
            .map_err(|_| AdminAccessError::Unavailable)
    }

    /// Performs exactly one fixed-cost derivation for syntactically valid real or dummy input.
    /// Missing verifiers always fail; short wrong passwords do not bypass the dummy computation.
    pub(crate) fn verify(
        &self,
        input: &str,
        verifier: Option<&AdminPasswordVerifier>,
    ) -> Result<bool, AdminAccessError> {
        let normalized = normalize(input)?;
        let salt = verifier.map_or(&[0xd0; 16], AdminPasswordVerifier::salt_bytes);
        let expected = verifier.map_or(&[0; 32], AdminPasswordVerifier::hash_bytes);
        let output = derive_password(&normalized, salt)?;
        Ok(bool::from(output[..].ct_eq(&expected[..])) & verifier.is_some())
    }
}

/// Human token/identifier and restore-generation entropy adapter.
/// Only purpose-bound token digests enter credential lookups; epochs are a separate value type.
pub struct AdminTokenCrypto {
    random: RandomFill,
}

impl AdminTokenCrypto {
    pub fn system() -> Self {
        Self {
            random: system_random,
        }
    }

    /// Rejects malformed or wrong-purpose material before deriving a lookup key.
    pub fn digest(
        &self,
        kind: AdminCredentialKind,
        raw: &str,
    ) -> Result<AdminCredentialDigest, AdminAccessError> {
        validate_token(kind, raw)?;
        let mut digest = Sha256::new();
        digest.update(b"fleet-human-credential-v1\0");
        digest.update(purpose(kind).1);
        digest.update([0]);
        digest.update(raw.as_bytes());
        Ok(AdminCredentialDigest::from_bytes(digest.finalize().into()))
    }

    /// Detects an encoded purpose for the setup form; it does not grant authentication authority.
    pub fn identify_purpose(raw: &str) -> Result<AdminCredentialKind, AdminAccessError> {
        for kind in [
            AdminCredentialKind::WebSession,
            AdminCredentialKind::PersonalToken,
            AdminCredentialKind::SetupGrant,
            AdminCredentialKind::ResetGrant,
        ] {
            if validate_token(kind, raw).is_ok() {
                return Ok(kind);
            }
        }
        Err(AdminAccessError::Unauthorized)
    }
}

impl HumanAuthEpochGenerator for AdminTokenCrypto {
    fn fresh_epoch(&self) -> Result<HumanAuthEpoch, AdminAccessError> {
        let mut bytes = [0; 16];
        (self.random)(&mut bytes)?;
        Ok(HumanAuthEpoch::from_bytes(bytes))
    }
}

impl AdminIdentityGenerator for AdminTokenCrypto {
    fn user_id(&self) -> Result<AdminUserId, AdminAccessError> {
        let mut bytes = [0; 16];
        (self.random)(&mut bytes)?;
        AdminUserId::parse(format!("usr_{}", hexadecimal(&bytes)))
            .map_err(|_| AdminAccessError::Unavailable)
    }

    fn credential(
        &self,
        kind: AdminCredentialKind,
    ) -> Result<AdminNewCredential, AdminAccessError> {
        let mut identifier = [0; 16];
        (self.random)(&mut identifier)?;
        let id = AdminCredentialId::parse(format!("crd_{}", hexadecimal(&identifier)))
            .map_err(|_| AdminAccessError::Unavailable)?;
        let mut bytes = Zeroizing::new([0; 32]);
        (self.random)(&mut bytes[..])?;
        let encoded = Zeroizing::new(hexadecimal(&bytes[..]));
        let raw = format!("{}{}", purpose(kind).0, encoded.as_str());
        let digest = self.digest(kind, &raw)?;
        Ok(AdminNewCredential {
            id,
            kind,
            digest,
            secret: AdminSecret::from_adapter(raw)?,
        })
    }
}

fn system_random(output: &mut [u8]) -> Result<(), AdminAccessError> {
    getrandom::getrandom(output).map_err(|_| AdminAccessError::Unavailable)
}

fn normalize(input: &str) -> Result<Zeroizing<String>, AdminAccessError> {
    if input.len() > 2_048 || input.chars().any(char::is_control) {
        return Err(AdminAccessError::InvalidRequest);
    }
    let normalized = Zeroizing::new(input.nfc().collect::<String>());
    if normalized.len() > 512 || normalized.chars().count() > 128 {
        return Err(AdminAccessError::InvalidRequest);
    }
    Ok(normalized)
}

fn weak_password(input: &str, username: &AdminUsername) -> bool {
    let folded = Zeroizing::new(input.to_lowercase());
    let common = [
        "passwordpassword",
        "passwordpassword1",
        "password12345678",
        "password123456789",
        "123456789012345",
        "12345678901234567890",
        "qwertyuiopasdfgh",
        "letmeinletmeinletmein",
        "fleetfleetfleet",
        "sponzeyfleet1234",
        "fleetadmin123456",
        "correcthorsebatterystaple",
    ];
    if common.contains(&folded.as_str()) {
        return true;
    }
    let mut characters = input.chars();
    let first = characters.next();
    if characters.all(|value| Some(value) == first) {
        return true;
    }
    let username = username.as_str();
    [
        username.to_owned(),
        format!("{username}123456789"),
        format!("{username}1234567890"),
        format!("{username}password"),
        format!("{username}password123"),
        format!("fleet{username}123"),
    ]
    .iter()
    .any(|guess| guess == folded.as_str())
}

fn derive_password(input: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, AdminAccessError> {
    let params = Params::new(19_456, 2, 1, Some(32)).map_err(|_| AdminAccessError::Unavailable)?;
    // Own the scratch allocation: the library's allocating helper does not wipe
    // its Blocks allocation on drop, even when its zeroize feature is enabled.
    let mut memory = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(params.block_count())
        .map_err(|_| AdminAccessError::Unavailable)?;
    memory.resize(params.block_count(), Block::new());
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0; 32]);
    kdf.hash_password_into_with_memory(input.as_bytes(), salt, &mut output[..], &mut memory[..])
        .map_err(|_| AdminAccessError::Unavailable)?;
    Ok(output)
}

fn purpose(kind: AdminCredentialKind) -> (&'static str, &'static [u8]) {
    match kind {
        AdminCredentialKind::WebSession => ("fws_", b"web-session"),
        AdminCredentialKind::PersonalToken => ("fpat_", b"personal-token"),
        AdminCredentialKind::SetupGrant => ("fsetup_", b"setup-grant"),
        AdminCredentialKind::ResetGrant => ("freset_", b"reset-grant"),
    }
}

fn validate_token(kind: AdminCredentialKind, raw: &str) -> Result<(), AdminAccessError> {
    let suffix = raw
        .strip_prefix(purpose(kind).0)
        .ok_or(AdminAccessError::Unauthorized)?;
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|value| value.is_ascii_digit() || matches!(value, b'a'..=b'f'))
    {
        return Err(AdminAccessError::Unauthorized);
    }
    Ok(())
}

fn hexadecimal(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 15) as usize]));
    }
    encoded
}

#[cfg(test)]
#[path = "admin_crypto_tests.rs"]
mod tests;
