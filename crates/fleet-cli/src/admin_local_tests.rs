use super::*;
use crate::{
    Cli, Command, ControllerAdminSubcommand, ControllerCommand, ControllerOwnerInitArgs,
    ControllerSubcommand,
};
use clap::Parser;
use fleet_application::admin_identity::{AdminAccessError, AdminIdentityRead};
use fleet_core::controller_data::{ControllerDataError, ControllerDataLease};
use fleet_domain::{AdminAuthMode, AdminRole, AdminUsername};
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;

#[path = "admin_recovery_tests.rs"]
mod recovery;

fn options(path: &std::path::Path) -> ControllerOwnerInitArgs {
    ControllerOwnerInitArgs {
        data_dir: path.to_path_buf(),
        db: None,
        username: "Leonard".to_owned(),
        display_name: Some("Local owner".to_owned()),
        password_stdin: true,
    }
}

fn password() -> Result<
    crate::admin_password_input::LocalPassword,
    crate::admin_password_input::PasswordInputError,
> {
    crate::admin_password_input::read_stdin(&mut Cursor::new(b"Cedar clouds beyond 47\n"))
}

#[test]
fn local_owner_cli_parses_metadata_and_rejects_password_arguments() {
    let cli = Cli::try_parse_from([
        "fleet",
        "controller",
        "admin",
        "init-owner",
        "--username",
        "Leonard",
        "--password-stdin",
        "--db",
        "sqlite://custom.db",
    ])
    .unwrap();
    let Command::Controller(ControllerCommand {
        command:
            ControllerSubcommand::Admin {
                command: ControllerAdminSubcommand::InitOwner(args),
            },
    }) = cli.command
    else {
        panic!("expected local owner command")
    };
    assert_eq!(args.db.as_deref(), Some("sqlite://custom.db"));
    assert!(args.password_stdin);
    assert!(!format!("{args:?}").contains("Cedar clouds"));
    for option in ["--password", "--password-file", "--password-env", "--role"] {
        assert!(
            Cli::try_parse_from([
                "fleet",
                "controller",
                "admin",
                "init-owner",
                "--username",
                "Leonard",
                option,
                "forbidden"
            ])
            .is_err()
        );
    }
}

#[test]
fn local_owner_actual_worker_initializes_empty_data_and_preserves_existing_identity_on_retry() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    let args = options(&path);
    let account = initialize_owner_with(&args, password).unwrap();
    assert_eq!(account.username.as_str(), "leonard");
    assert_eq!(account.role, AdminRole::Owner);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let key = std::fs::read(path.join("controller/controller_private.key")).unwrap();
    let store = fleet_store::SqliteStore::open(path.join("controller/fleet.db")).unwrap();
    assert_eq!(store.auth_state().unwrap().mode, AdminAuthMode::Personal);
    assert_eq!(store.loginable_owner_count().unwrap(), 1);
    assert!(!store.verify_admin_token_hash("old-shared-fixture").unwrap());
    assert_eq!(
        store
            .account_by_username(&AdminUsername::parse("leonard").unwrap())
            .unwrap()
            .unwrap()
            .snapshot()
            .id,
        account.id
    );
    drop(store);
    assert!(matches!(
        initialize_owner_with(&args, password),
        Err(crate::CliError::AdminIdentity(AdminAccessError::Conflict))
    ));
    assert_eq!(
        std::fs::read(path.join("controller/controller_private.key")).unwrap(),
        key
    );
}

#[test]
fn local_owner_uses_exact_custom_sqlite_path_and_rejects_unsupported_backend_before_input() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    let custom = root.path().join("custom.db");
    let mut args = options(&path);
    args.db = Some(format!("sqlite://{}", custom.display()));
    initialize_owner_with(&args, password).unwrap();
    assert!(!path.join("controller/fleet.db").exists());
    assert_eq!(
        fleet_store::SqliteStore::open(&custom)
            .unwrap()
            .auth_state()
            .unwrap()
            .mode,
        AdminAuthMode::Personal
    );
    let other = root.path().join("unsupported");
    args.data_dir = other.clone();
    args.db = Some("postgresql://fixture:never-print@127.0.0.1/unused".to_owned());
    let error = initialize_owner_with(&args, || {
        panic!("unsupported DB must fail before password input")
    })
    .unwrap_err();
    assert!(matches!(error, crate::CliError::AdminLocalRequiresSqlite));
    assert!(!other.exists());
    assert!(!format!("{error:?} {error}").contains("never-print"));
}

#[test]
fn local_owner_busy_unsafe_or_input_failure_cannot_create_database_or_identity() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    let args = options(&path);
    let lease = ControllerDataLease::acquire(&path).unwrap();
    let error = initialize_owner_with(&args, || panic!("busy before input")).unwrap_err();
    assert_eq!(error.to_string(), ControllerDataError::Busy.to_string());
    drop(lease);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let error = initialize_owner_with(&args, || panic!("unsafe before input")).unwrap_err();
    assert_eq!(
        error.to_string(),
        ControllerDataError::UnsafeDirectory.to_string()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        initialize_owner_with(&args, || Err(
            crate::admin_password_input::PasswordInputError::Cancelled
        )),
        Err(crate::CliError::AdminInput(_))
    ));
    assert!(!path.join("controller").exists());
    let _next = ControllerDataLease::acquire(&path).unwrap();
}

#[test]
fn local_owner_retry_cannot_regenerate_missing_agent_trust_identity() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    let args = options(&path);
    initialize_owner_with(&args, password).unwrap();
    for name in ["controller_public.key", "controller_private.key"] {
        let file = path.join("controller").join(name);
        std::fs::rename(&file, file.with_extension("fixture-preserved")).unwrap();
    }
    assert!(matches!(
        initialize_owner_with(&args, password),
        Err(crate::CliError::AdminIdentity(AdminAccessError::Conflict))
    ));
    assert!(!path.join("controller/controller_public.key").exists());
    assert!(!path.join("controller/controller_private.key").exists());
}

#[test]
fn local_owner_cutover_rejects_actual_old_token_and_keeps_its_history_row() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    let lease = ControllerDataLease::acquire(&path).unwrap();
    prepare_controller_dir(&path).unwrap();
    let store = fleet_store::SqliteStore::open(path.join("controller/fleet.db")).unwrap();
    let token = fleet_controller::create_admin_token(&store)
        .unwrap()
        .unwrap();
    let digest = fleet_controller::hash_token(&token);
    assert!(store.verify_admin_token_hash(&digest).unwrap());
    drop(store);
    drop(lease);
    initialize_owner_with(&options(&path), password).unwrap();
    let store = fleet_store::SqliteStore::open(path.join("controller/fleet.db")).unwrap();
    assert!(store.admin_token_exists().unwrap());
    assert!(!store.verify_admin_token_hash(&digest).unwrap());
    assert!(store.find_admin_token_record(&digest).unwrap().is_none());
    let events = store.list_audit_events(10).unwrap();
    let initialized = events
        .iter()
        .find(|event| event.action == "admin_owner_initialized")
        .unwrap();
    assert_eq!(
        initialized.actor.as_str(),
        format!("local-os:{}", rustix::process::geteuid().as_raw())
    );
    assert!(!format!("{initialized:?}").contains(&token));
}

#[test]
fn local_controller_init_uses_lease_private_new_dir_and_preserves_keys_on_reinit() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    let init = || {
        crate::execute_controller(ControllerCommand {
            command: ControllerSubcommand::Init {
                data_dir: path.clone(),
                db: None,
            },
        })
    };
    let lease = ControllerDataLease::acquire(&path).unwrap();
    assert_eq!(
        init().unwrap_err().to_string(),
        ControllerDataError::Busy.to_string()
    );
    assert!(!path.join("controller").exists());
    drop(lease);
    init().unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let key = std::fs::read(path.join("controller/controller_private.key")).unwrap();
    init().unwrap();
    assert_eq!(
        std::fs::read(path.join("controller/controller_private.key")).unwrap(),
        key
    );
    let store = fleet_store::SqliteStore::open(path.join("controller/fleet.db")).unwrap();
    assert!(store.admin_token_exists().unwrap());
    assert!(
        fleet_controller::create_admin_token(&store)
            .unwrap()
            .is_none()
    );
}

#[test]
fn local_controller_init_after_personal_setup_never_creates_shared_token() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    initialize_owner_with(&options(&path), password).unwrap();
    crate::execute_controller(ControllerCommand {
        command: ControllerSubcommand::Init {
            data_dir: path.clone(),
            db: None,
        },
    })
    .unwrap();
    let store = fleet_store::SqliteStore::open(path.join("controller/fleet.db")).unwrap();
    assert_eq!(store.auth_state().unwrap().mode, AdminAuthMode::Personal);
    assert!(!store.admin_token_exists().unwrap());
}

#[test]
fn local_controller_init_accepts_the_same_custom_database_as_owner_and_start() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    let custom = root.path().join("custom.db");
    let mut args = options(&path);
    args.db = Some(format!("sqlite://{}", custom.display()));
    initialize_owner_with(&args, password).unwrap();
    let cli = Cli::try_parse_from([
        "fleet",
        "controller",
        "init",
        "--data-dir",
        path.to_str().unwrap(),
        "--db",
        args.db.as_deref().unwrap(),
    ])
    .unwrap();
    crate::execute(cli).unwrap();
    assert!(!path.join("controller/fleet.db").exists());
    let store = fleet_store::SqliteStore::open(&custom).unwrap();
    assert!(!store.admin_token_exists().unwrap());
    assert_eq!(store.auth_state().unwrap().mode, AdminAuthMode::Personal);
}

#[test]
fn local_controller_reinit_cannot_replace_missing_personal_signing_identity() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    initialize_owner_with(&options(&path), password).unwrap();
    for name in ["controller_public.key", "controller_private.key"] {
        let file = path.join("controller").join(name);
        std::fs::rename(&file, file.with_extension("fixture-preserved")).unwrap();
    }
    assert!(
        crate::execute_controller(ControllerCommand {
            command: ControllerSubcommand::Init {
                data_dir: path.clone(),
                db: None
            }
        })
        .is_err()
    );
    assert!(!path.join("controller/controller_public.key").exists());
    assert!(!path.join("controller/controller_private.key").exists());
}

#[test]
fn local_demo_still_completes_under_the_controller_data_lease() {
    crate::execute_demo(crate::DemoCommand {
        keep_temp: false,
        port: None,
    })
    .unwrap();
}

#[test]
fn demo_output_read_waits_for_storage_without_reexecuting_the_job() {
    let mut reads = 0;
    let output = crate::wait_for_demo_output(
        || {
            reads += 1;
            Ok(if reads == 1 { "[]" } else { "demo-ok" }.to_owned())
        },
        |_| {},
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(output, "demo-ok");
    assert_eq!(reads, 2);
}

#[test]
fn demo_output_wait_deadline_and_read_error_cannot_report_success() {
    assert!(
        crate::wait_for_demo_output(|| Ok("[]".to_owned()), |_| {}, std::time::Duration::ZERO)
            .is_err()
    );
    assert!(
        crate::wait_for_demo_output(
            || Err(crate::CliError::Http("unavailable".to_owned())),
            |_| panic!("read error must stop"),
            std::time::Duration::from_secs(1)
        )
        .is_err()
    );
}

#[test]
fn local_owner_invalid_password_or_database_preserves_legacy_access() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data");
    let lease = ControllerDataLease::acquire(&path).unwrap();
    prepare_controller_dir(&path).unwrap();
    let store = fleet_store::SqliteStore::open(path.join("controller/fleet.db")).unwrap();
    let token = fleet_controller::create_admin_token(&store)
        .unwrap()
        .unwrap();
    let digest = fleet_controller::hash_token(&token);
    let before = store.auth_state().unwrap();
    let audits = store.list_audit_events(10).unwrap();
    drop(store);
    drop(lease);
    let mut args = options(&path);
    assert!(matches!(
        initialize_owner_with(&args, || crate::admin_password_input::read_stdin(
            &mut Cursor::new(b"short\n")
        )),
        Err(crate::CliError::AdminIdentity(
            AdminAccessError::InvalidRequest
        ))
    ));
    let broken = root.path().join("unreadable.sqlite3");
    std::fs::write(&broken, b"not a SQLite database").unwrap();
    args.db = Some(format!("sqlite://{}", broken.display()));
    let error = initialize_owner_with(&args, password).unwrap_err();
    assert!(matches!(
        error,
        crate::CliError::AdminIdentity(AdminAccessError::Unavailable)
    ));
    assert_eq!(std::fs::read(&broken).unwrap(), b"not a SQLite database");
    let store = fleet_store::SqliteStore::open(path.join("controller/fleet.db")).unwrap();
    assert_eq!(store.auth_state().unwrap(), before);
    assert_eq!(store.loginable_owner_count().unwrap(), 0);
    assert_eq!(store.list_audit_events(10).unwrap(), audits);
    assert!(store.verify_admin_token_hash(&digest).unwrap());
    let _lease = ControllerDataLease::acquire(&path).unwrap();
}
