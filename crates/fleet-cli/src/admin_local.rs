//! Local OS-authorized administrator setup; no remote route can construct this authority.

use crate::admin_password_input::{LocalPassword, PasswordInputError};
use crate::{CliError, ControllerOwnerInitArgs, ControllerOwnerRecoveryArgs};
use fleet_application::admin_identity::{
    AdminAccessError, AdminAccountSummary, AdminIdentityRead, AdminLocalAuthority,
    InitializeAdminOwner, InitializeOwnerInput, InvalidateAdminCredentialsAfterRestore,
    RecoverAdminOwner, RecoverOwnerInput,
};
use fleet_controller::admin_crypto::{AdminAuthSettings, AdminTokenCrypto};
use fleet_controller::admin_password_worker::{AdminAuthRequest, AdminPasswordWorker};
use fleet_core::controller_data::ControllerDataLease;
use fleet_domain::{AdminDisplayName, AdminUsername, AuditActor};
use std::path::Path;

struct LocalAuthority<'a> {
    _lease: &'a ControllerDataLease,
    actor: AuditActor,
}

impl AdminLocalAuthority for LocalAuthority<'_> {
    fn require_exclusive(&self) -> Result<AuditActor, AdminAccessError> {
        Ok(self.actor.clone())
    }
}

impl<'a> LocalAuthority<'a> {
    fn for_lease(lease: &'a ControllerDataLease) -> Self {
        #[cfg(unix)]
        let actor = AuditActor::new(format!("local-os:{}", rustix::process::geteuid().as_raw()));
        #[cfg(not(unix))]
        let actor = AuditActor::new("unsupported-local-authority"); // acquire already fails closed.
        Self {
            _lease: lease,
            actor,
        }
    }
}

/// Consumes only a private, validated restore candidate under the target's OS lease.
/// No password worker is needed: this operation generates a new human epoch and commits its audit.
pub(super) fn invalidate_restored_human_credentials(
    store: &mut fleet_store::SqliteStore,
    lease: &ControllerDataLease,
) -> Result<fleet_domain::AdminAuthMode, CliError> {
    let authority = LocalAuthority::for_lease(lease);
    let request = AdminAuthRequest::new(AdminAuthSettings::new(1)?)?;
    Ok(InvalidateAdminCredentialsAfterRestore::execute(
        store,
        &authority,
        &request.operation(),
        &AdminTokenCrypto::system(),
    )?)
}

/// Caller holds the Core data-dir lease; existing final directory symlinks are rejected.
pub(super) fn prepare_controller_dir(data_dir: &Path) -> Result<(), CliError> {
    let path = crate::controller_dir(data_dir);
    let mut directory = std::fs::DirBuilder::new();
    directory.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory
        .create(&path)
        .map_err(|_| AdminAccessError::Unavailable)?;
    if !std::fs::symlink_metadata(path)
        .map_err(|_| AdminAccessError::Unavailable)?
        .is_dir()
    {
        return Err(AdminAccessError::Unavailable.into());
    }
    Ok(())
}

/// Personal/restored modes must retain the signing identity already trusted by Agents.
pub(super) fn bootstrap_signing_identity(
    data_dir: &Path,
    mode: fleet_domain::AdminAuthMode,
) -> Result<String, CliError> {
    if mode != fleet_domain::AdminAuthMode::LegacyBootstrap {
        crate::ensure_controller_initialized_for_start(data_dir)
            .map_err(|_| CliError::MissingControllerSigningIdentity)?;
    }
    crate::ensure_controller_identity(data_dir).map_err(|_| AdminAccessError::Unavailable)?;
    let directory = crate::controller_dir(data_dir);
    let public = std::fs::read_to_string(directory.join("controller_public.key"))
        .map_err(|_| AdminAccessError::Unavailable)?;
    let private = zeroize::Zeroizing::new(
        std::fs::read_to_string(directory.join("controller_private.key"))
            .map_err(|_| AdminAccessError::Unavailable)?,
    );
    let validated = fleet_core::validate_signing_material_pair(
        public.trim(),
        private.trim(),
        "fleet-local-admin-signing-validation",
    )
    .map_err(|_| CliError::InvalidControllerSigningIdentity)?;
    Ok(validated.public_key_fingerprint)
}

/// Holds OS authority from before input/storage access until password worker shutdown.
/// Application owns the account/mode/audit transaction; no raw password is persisted.
pub(super) fn initialize_owner_with(
    args: &ControllerOwnerInitArgs,
    input: impl FnOnce() -> Result<LocalPassword, PasswordInputError>,
) -> Result<AdminAccountSummary, CliError> {
    let username = AdminUsername::parse(&args.username).map_err(AdminAccessError::from)?;
    let display_name =
        AdminDisplayName::parse(args.display_name.as_deref().unwrap_or(&args.username))
            .map_err(AdminAccessError::from)?;
    let database = crate::parse_controller_database_settings(args.db.as_deref(), &args.data_dir)
        .map_err(|_| AdminAccessError::InvalidRequest)?;
    let path = database
        .sqlite_path()
        .ok_or(CliError::AdminLocalRequiresSqlite)?;
    let lease = ControllerDataLease::acquire(&args.data_dir)?;
    let authority = LocalAuthority::for_lease(&lease);
    let password = input()?;
    prepare_controller_dir(&args.data_dir)?;
    let mut store =
        fleet_store::SqliteStore::open(path).map_err(|_| AdminAccessError::Unavailable)?;
    let mode = store.auth_state()?.mode;
    if mode == fleet_domain::AdminAuthMode::Personal {
        return Err(AdminAccessError::Conflict.into());
    }
    bootstrap_signing_identity(&args.data_dir, mode)?;
    let settings = AdminAuthSettings::new(1)?;
    let worker = AdminPasswordWorker::spawn(settings)?;
    let client = worker.client();
    let request = AdminAuthRequest::new(settings)?;
    let operation = request.operation();
    let result = InitializeAdminOwner::execute(
        &mut store,
        &authority,
        &operation,
        &client.passwords(&operation),
        &AdminTokenCrypto::system(),
        InitializeOwnerInput {
            username,
            display_name,
            new_password: password.expose(),
        },
    );
    let stopped = worker.shutdown();
    let account = result?;
    stopped?;
    Ok(account)
}

/// Recovers one existing person's owner access under the held OS lease.
/// The immutable user ID comes from the selected store, never from a claimed actor/role.
pub(super) fn recover_owner_with(
    args: &ControllerOwnerRecoveryArgs,
    input: impl FnOnce() -> Result<LocalPassword, PasswordInputError>,
) -> Result<AdminAccountSummary, CliError> {
    let username = AdminUsername::parse(&args.username).map_err(AdminAccessError::from)?;
    let database = crate::parse_controller_database_settings(args.db.as_deref(), &args.data_dir)
        .map_err(|_| AdminAccessError::InvalidRequest)?;
    let path = database
        .sqlite_path()
        .ok_or(CliError::AdminLocalRequiresSqlite)?;
    let lease = ControllerDataLease::acquire(&args.data_dir)?;
    let authority = LocalAuthority::for_lease(&lease);
    if !path.is_file() {
        return Err(AdminAccessError::NotFound.into());
    }
    bootstrap_signing_identity(&args.data_dir, fleet_domain::AdminAuthMode::Personal)?;
    let mut store =
        fleet_store::SqliteStore::open(path).map_err(|_| AdminAccessError::Unavailable)?;
    if store.auth_state()?.mode == fleet_domain::AdminAuthMode::LegacyBootstrap {
        return Err(AdminAccessError::Conflict.into());
    }
    let account = store
        .account_by_username(&username)?
        .ok_or(AdminAccessError::NotFound)?;
    let password = input()?;
    let settings = AdminAuthSettings::new(1)?;
    let worker = AdminPasswordWorker::spawn(settings)?;
    let client = worker.client();
    let request = AdminAuthRequest::new(settings)?;
    let operation = request.operation();
    let result = RecoverAdminOwner::execute(
        &mut store,
        &authority,
        &operation,
        &client.passwords(&operation),
        RecoverOwnerInput {
            user_id: account.snapshot().id,
            new_password: password.expose(),
        },
    );
    let stopped = worker.shutdown();
    let account = result?;
    stopped?;
    Ok(account)
}

#[cfg(all(test, unix))]
#[path = "admin_local_tests.rs"]
mod tests;
