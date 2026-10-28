use super::*;
use fleet_application::admin_identity::{
    AdminAccessError, AdminIdentityGenerator, HumanAuthEpochGenerator,
};
use fleet_domain::{AdminCredentialKind, AdminPasswordVerifier, AdminUsername};
use std::time::Duration;

fn username() -> AdminUsername {
    AdminUsername::parse("fixture_user").unwrap()
}

#[test]
fn settings_accept_only_the_measured_worker_range_and_fixed_limits() {
    for workers in [0, 3, usize::MAX] {
        assert_eq!(
            AdminAuthSettings::new(workers).unwrap_err(),
            AdminAccessError::InvalidRequest
        );
    }
    let settings = AdminAuthSettings::new(1).unwrap();
    assert_eq!(settings.worker_count(), 1);
    assert_eq!(settings.pending_capacity(), 1);
    assert_eq!(settings.auth_timeout(), Duration::from_secs(30));
    assert_eq!(AdminAuthSettings::new(2).unwrap().worker_count(), 2);
}

#[test]
fn fixed_argon2_profile_has_unique_salts_and_verifies_correct_wrong_and_dummy_input() {
    let crypto = AdminPasswordPrimitives::system();
    let first = crypto
        .hash_new("synthetic fixture passphrase", &username())
        .unwrap();
    let second = crypto
        .hash_new("synthetic fixture passphrase", &username())
        .unwrap();
    assert_ne!(first.salt_bytes(), second.salt_bytes());
    assert_ne!(first.hash_bytes(), second.hash_bytes());
    assert!(
        crypto
            .verify("synthetic fixture passphrase", Some(&first))
            .unwrap()
    );
    assert!(
        !crypto
            .verify("different fixture passphrase", Some(&first))
            .unwrap()
    );
    assert!(!crypto.verify("synthetic fixture passphrase", None).unwrap());
    assert_eq!(format!("{first:?}"), "AdminPasswordVerifier([REDACTED])");
    assert!(
        AdminPasswordVerifier::from_parts(
            "argon2id-v19-m999999-t2-p1",
            first.salt_bytes(),
            first.hash_bytes()
        )
        .is_err()
    );
}

#[test]
fn password_normalization_is_nfc_and_does_not_trim_or_change_case() {
    let crypto = AdminPasswordPrimitives::system();
    let verifier = crypto
        .hash_new("long cafe\u{301} fixture passphrase", &username())
        .unwrap();
    assert!(
        crypto
            .verify("long café fixture passphrase", Some(&verifier))
            .unwrap()
    );
    assert!(
        !crypto
            .verify("Long café fixture passphrase", Some(&verifier))
            .unwrap()
    );
    let spaced = crypto
        .hash_new("  spaced fixture passphrase  ", &username())
        .unwrap();
    assert!(
        crypto
            .verify("  spaced fixture passphrase  ", Some(&spaced))
            .unwrap()
    );
    assert!(
        !crypto
            .verify("spaced fixture passphrase", Some(&spaced))
            .unwrap()
    );
}

#[test]
fn malformed_weak_and_oversized_passwords_are_rejected_before_crypto() {
    let crypto = AdminPasswordPrimitives {
        random: random_must_not_run,
    };
    for password in [
        "short".to_owned(),
        "a".repeat(15),
        "passwordpassword".to_owned(),
        "x".repeat(129),
        "x".repeat(2_049),
        "line\nbreak fixture password".to_owned(),
    ] {
        assert_eq!(
            crypto.hash_new(&password, &username()).unwrap_err(),
            AdminAccessError::InvalidRequest
        );
    }
    assert_eq!(
        crypto
            .hash_new(
                "administrator123456789",
                &AdminUsername::parse("administrator").unwrap()
            )
            .unwrap_err(),
        AdminAccessError::InvalidRequest
    );
    assert_eq!(
        crypto.verify(&"x".repeat(2_049), None).unwrap_err(),
        AdminAccessError::InvalidRequest
    );
    assert_eq!(
        crypto.verify(&"😀".repeat(129), None).unwrap_err(),
        AdminAccessError::InvalidRequest
    );
    let full = "😀😁".repeat(64);
    assert_eq!(full.len(), 512);
    let verifier = AdminPasswordPrimitives::system()
        .hash_new(&full, &username())
        .unwrap();
    assert!(
        AdminPasswordPrimitives::system()
            .verify(&full, Some(&verifier))
            .unwrap()
    );
}

fn random_must_not_run(_: &mut [u8]) -> Result<(), AdminAccessError> {
    panic!("input validation must precede salt allocation")
}

fn random_fails(_: &mut [u8]) -> Result<(), AdminAccessError> {
    Err(AdminAccessError::Unavailable)
}

#[test]
fn entropy_failure_is_closed_and_contains_no_input_or_provider_error() {
    let crypto = AdminPasswordPrimitives {
        random: random_fails,
    };
    let error = crypto
        .hash_new("synthetic sentinel passphrase", &username())
        .unwrap_err();
    assert_eq!(error, AdminAccessError::Unavailable);
    assert!(!error.to_string().contains("sentinel"));
    let tokens = AdminTokenCrypto {
        random: random_fails,
    };
    assert_eq!(tokens.user_id().unwrap_err(), AdminAccessError::Unavailable);
    assert_eq!(
        tokens
            .credential(AdminCredentialKind::PersonalToken)
            .unwrap_err(),
        AdminAccessError::Unavailable
    );
}

#[test]
fn human_restore_epochs_use_independent_entropy_and_fail_closed() {
    let crypto = AdminTokenCrypto::system();
    let first = crypto.fresh_epoch().unwrap();
    assert_ne!(first, crypto.fresh_epoch().unwrap());
    assert_eq!(format!("{first:?}"), "HumanAuthEpoch([REDACTED])");
    let unavailable = AdminTokenCrypto {
        random: random_fails,
    };
    assert_eq!(
        unavailable.fresh_epoch().unwrap_err(),
        AdminAccessError::Unavailable
    );
}

#[test]
fn issued_tokens_have_independent_ids_purposes_and_redacted_delivery_material() {
    let tokens = AdminTokenCrypto::system();
    assert_ne!(tokens.user_id().unwrap(), tokens.user_id().unwrap());
    let mut previous = None;
    for kind in [
        AdminCredentialKind::WebSession,
        AdminCredentialKind::PersonalToken,
        AdminCredentialKind::SetupGrant,
        AdminCredentialKind::ResetGrant,
    ] {
        let issued = tokens.credential(kind).unwrap();
        let raw = issued.secret.expose_for_delivery();
        assert_eq!(AdminTokenCrypto::identify_purpose(raw).unwrap(), kind);
        assert_eq!(tokens.digest(kind, raw).unwrap(), issued.digest);
        for other in [
            AdminCredentialKind::WebSession,
            AdminCredentialKind::PersonalToken,
            AdminCredentialKind::SetupGrant,
            AdminCredentialKind::ResetGrant,
        ]
        .into_iter()
        .filter(|other| *other != kind)
        {
            assert_eq!(
                tokens.digest(other, raw).unwrap_err(),
                AdminAccessError::Unauthorized
            );
        }
        assert!(!format!("{issued:?}").contains(raw));
        if let Some(previous) = previous {
            assert_ne!(issued.id, previous);
        }
        previous = Some(issued.id);
    }
}

#[test]
fn malformed_secret_encodings_never_become_digest_lookup_keys() {
    let tokens = AdminTokenCrypto::system();
    let issued = tokens
        .credential(AdminCredentialKind::PersonalToken)
        .unwrap();
    let raw = issued.secret.expose_for_delivery();
    for invalid in [
        format!(" {raw}"),
        format!("{raw} "),
        raw.to_uppercase(),
        raw[..raw.len() - 1].to_owned(),
        "x".repeat(300),
    ] {
        assert_eq!(
            tokens
                .digest(AdminCredentialKind::PersonalToken, &invalid)
                .unwrap_err(),
            AdminAccessError::Unauthorized
        );
        assert_eq!(
            AdminTokenCrypto::identify_purpose(&invalid).unwrap_err(),
            AdminAccessError::Unauthorized
        );
    }
}
