use super::*;
use crate::ControllerOwnerRecoveryArgs;
use fleet_application::admin_identity::{
    AdminIdentityRepository, AdminOperation, AdminPasswordPort, AuthenticateAdminCredential,
};
use fleet_domain::{
    AdminAccount, AdminCredential, AdminCredentialBinding, AdminCredentialDigest,
    AdminCredentialId, AdminCredentialKind, AdminDisplayName, AdminPasswordVerifier, AdminUserId,
};

fn recovery(path: &std::path::Path) -> ControllerOwnerRecoveryArgs {
    ControllerOwnerRecoveryArgs {
        data_dir: path.to_path_buf(),
        db: None,
        username: "LEONARD".to_owned(),
        password_stdin: true,
    }
}

fn replacement() -> Result<crate::admin_password_input::LocalPassword, crate::PasswordInputError> {
    crate::admin_password_input::read_stdin(&mut Cursor::new(b"Lanterns under winter skies 92\n"))
}

fn seed_credential(
    store: &mut fleet_store::SqliteStore,
    user: &AdminUserId,
    marker: u8,
    kind: AdminCredentialKind,
) -> AdminCredentialDigest {
    let request = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
    let operation = request.operation();
    let digest = AdminCredentialDigest::from_bytes([marker; 32]);
    store
        .identity_transaction(|tx| {
            let account = tx.account_by_id(user)?.unwrap();
            let epoch = tx.auth_state()?.epoch;
            let credential = AdminCredential::issue(
                AdminCredentialId::parse(format!("crd_{marker:032x}")).unwrap(),
                kind,
                digest.clone(),
                AdminCredentialBinding::for_account(&account, epoch),
                operation.checked_now()? - 1,
            )
            .unwrap();
            tx.insert_credential(&credential.snapshot())
        })
        .unwrap();
    AuthenticateAdminCredential::execute(store, &operation, kind, &digest).unwrap();
    digest
}

#[test]
fn local_recovery_cli_parses_only_local_metadata_and_redacts_database_configuration() {
    let cli = Cli::try_parse_from([
        "fleet",
        "controller",
        "admin",
        "recover-owner",
        "--username",
        "LEONARD",
        "--password-stdin",
        "--db",
        "sqlite://custom.db",
    ])
    .unwrap();
    let Command::Controller(ControllerCommand {
        command:
            ControllerSubcommand::Admin {
                command: ControllerAdminSubcommand::RecoverOwner(mut args),
            },
    }) = cli.command
    else {
        panic!("expected recovery command")
    };
    assert_eq!(args.username, "LEONARD");
    assert!(args.password_stdin);
    args.db = Some("postgresql://fixture:never-print@127.0.0.1/unused".to_owned());
    assert!(!format!("{args:?}").contains("never-print"));
    for option in [
        "--password",
        "--password-env",
        "--password-file",
        "--role",
        "--actor",
        "--display-name",
        "--current-password",
    ] {
        assert!(
            Cli::try_parse_from([
                "fleet",
                "controller",
                "admin",
                "recover-owner",
                "--username",
                "LEONARD",
                option,
                "forbidden"
            ])
            .is_err()
        );
    }
}

#[test]
fn local_recovery_actual_crypto_changes_only_selected_person_and_revokes_old_credentials() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    let owner = initialize_owner_with(&options(&path), password).unwrap();
    let mut store = fleet_store::SqliteStore::open(path.join("controller/fleet.db")).unwrap();
    let before = store.account_by_id(&owner.id).unwrap().unwrap().snapshot();
    let auth = store.auth_state().unwrap();
    let mut other = AdminAccount::pending(
        AdminUserId::parse(format!("usr_{:032x}", 2)).unwrap(),
        AdminUsername::parse("other.user").unwrap(),
        AdminDisplayName::parse("Other fixture").unwrap(),
        AdminRole::Viewer,
    );
    // This non-target verifier is synthetic; the target's old/new password crypto is real.
    other
        .install_password(
            AdminPasswordVerifier::from_parts(
                AdminPasswordVerifier::PROFILE_ID,
                &[6; 16],
                &[7; 32],
            )
            .unwrap(),
        )
        .unwrap();
    let other = other.snapshot();
    store
        .identity_transaction(|tx| tx.insert_account(&other))
        .unwrap();
    let session = seed_credential(&mut store, &owner.id, 1, AdminCredentialKind::WebSession);
    let pat = seed_credential(&mut store, &owner.id, 2, AdminCredentialKind::PersonalToken);
    let other_pat = seed_credential(&mut store, &other.id, 3, AdminCredentialKind::PersonalToken);
    let keys: Vec<_> = ["controller_public.key", "controller_private.key"]
        .iter()
        .map(|name| std::fs::read(path.join("controller").join(name)).unwrap())
        .collect();
    drop(store);
    let recovered = recover_owner_with(&recovery(&path), replacement).unwrap();
    assert_eq!(recovered.id, owner.id);
    assert_eq!(recovered.username, owner.username);
    assert_eq!(recovered.display_name, owner.display_name);
    let store = fleet_store::SqliteStore::open(path.join("controller/fleet.db")).unwrap();
    let after = store.account_by_id(&owner.id).unwrap().unwrap().snapshot();
    assert_eq!(
        after.credential_revision.value(),
        before.credential_revision.value() + 1
    );
    assert_eq!(store.auth_state().unwrap(), auth);
    assert_eq!(
        store.account_by_id(&other.id).unwrap().unwrap().snapshot(),
        other
    );
    let settings = AdminAuthSettings::new(1).unwrap();
    let request = AdminAuthRequest::new(settings).unwrap();
    let operation = request.operation();
    for (kind, digest) in [
        (AdminCredentialKind::WebSession, session),
        (AdminCredentialKind::PersonalToken, pat),
    ] {
        assert_eq!(
            AuthenticateAdminCredential::execute(&store, &operation, kind, &digest).unwrap_err(),
            AdminAccessError::Unauthorized
        );
        assert!(store.credential_by_digest(kind, &digest).unwrap().is_none());
    }
    AuthenticateAdminCredential::execute(
        &store,
        &operation,
        AdminCredentialKind::PersonalToken,
        &other_pat,
    )
    .unwrap();
    let worker = AdminPasswordWorker::spawn(settings).unwrap();
    let client = worker.client();
    assert!(
        !client
            .passwords(&operation)
            .verify("Cedar clouds beyond 47", after.password_verifier.as_ref())
            .unwrap()
    );
    assert!(
        client
            .passwords(&operation)
            .verify(
                "Lanterns under winter skies 92",
                after.password_verifier.as_ref()
            )
            .unwrap()
    );
    worker.shutdown().unwrap();
    let audit = store
        .list_audit_events(20)
        .unwrap()
        .into_iter()
        .find(|event| event.action == "admin_owner_recovered")
        .unwrap();
    assert_eq!(
        audit.actor.as_str(),
        format!("local-os:{}", rustix::process::geteuid().as_raw())
    );
    assert_eq!(audit.target.as_str(), owner.id.as_str());
    let current_keys: Vec<_> = ["controller_public.key", "controller_private.key"]
        .iter()
        .map(|name| std::fs::read(path.join("controller").join(name)).unwrap())
        .collect();
    assert!(
        current_keys == keys,
        "recovery must preserve signing material"
    );
}

#[test]
fn local_recovery_busy_unknown_user_or_cancelled_input_preserves_account() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    let owner = initialize_owner_with(&options(&path), password).unwrap();
    let read = || {
        fleet_store::SqliteStore::open(path.join("controller/fleet.db"))
            .unwrap()
            .account_by_id(&owner.id)
            .unwrap()
            .unwrap()
            .snapshot()
    };
    let before = read();
    let mut args = recovery(&path);
    let lease = ControllerDataLease::acquire(&path).unwrap();
    let error = recover_owner_with(&args, || panic!("busy before input")).unwrap_err();
    assert_eq!(error.to_string(), ControllerDataError::Busy.to_string());
    drop(lease);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let error = recover_owner_with(&args, || panic!("unsafe directory before input")).unwrap_err();
    assert_eq!(
        error.to_string(),
        ControllerDataError::UnsafeDirectory.to_string()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    args.username = "missing.user".to_owned();
    assert!(matches!(
        recover_owner_with(&args, || panic!("unknown before input")),
        Err(crate::CliError::AdminIdentity(AdminAccessError::NotFound))
    ));
    args.username = "Leonard".to_owned();
    assert!(matches!(
        recover_owner_with(&args, || Err(crate::PasswordInputError::Cancelled)),
        Err(crate::CliError::AdminInput(_))
    ));
    assert!(matches!(
        recover_owner_with(&args, || crate::admin_password_input::read_stdin(
            &mut Cursor::new(b"short\n")
        )),
        Err(crate::CliError::AdminIdentity(
            AdminAccessError::InvalidRequest
        ))
    ));
    args.db = Some("postgresql://fixture:never-print@127.0.0.1/unused".to_owned());
    let error =
        recover_owner_with(&args, || panic!("unsupported backend before input")).unwrap_err();
    assert!(matches!(error, crate::CliError::AdminLocalRequiresSqlite));
    assert!(!format!("{error:?} {error}").contains("never-print"));
    assert_eq!(read(), before);
    let _lease = ControllerDataLease::acquire(&path).unwrap();
}

#[test]
fn local_recovery_uses_custom_database_and_rejects_missing_or_mismatched_original_keys() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    let custom = root.path().join("custom.db");
    let mut setup = options(&path);
    setup.db = Some(format!("sqlite://{}", custom.display()));
    let owner = initialize_owner_with(&setup, password).unwrap();
    let mut args = recovery(&path);
    args.db = setup.db.clone();
    recover_owner_with(&args, replacement).unwrap();
    assert!(!path.join("controller/fleet.db").exists());
    let read = || {
        fleet_store::SqliteStore::open(&custom)
            .unwrap()
            .account_by_id(&owner.id)
            .unwrap()
            .unwrap()
            .snapshot()
    };
    let before = read();
    let private = path.join("controller/controller_private.key");
    let original = std::fs::read(&private).unwrap();
    std::fs::remove_file(&private).unwrap();
    assert!(matches!(
        recover_owner_with(&args, || panic!("missing key before input")),
        Err(crate::CliError::MissingControllerSigningIdentity)
    ));
    assert!(!private.exists());
    assert_eq!(read(), before);
    std::fs::write(&private, &original).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600)).unwrap();
    let wrong = fleet_core::generate_agent_key_pair().unwrap();
    std::fs::write(&private, &wrong.private_key_hex).unwrap();
    let error = recover_owner_with(&args, || panic!("mismatched key before input")).unwrap_err();
    assert!(matches!(
        error,
        crate::CliError::InvalidControllerSigningIdentity
    ));
    assert!(!format!("{error:?} {error}").contains(&wrong.private_key_hex));
    assert!(!format!("{error:?} {error}").contains(private.to_str().unwrap()));
    assert_eq!(read(), before);
}
