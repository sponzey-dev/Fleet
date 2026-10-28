//! Typed canonical business-write adapters and safe HTTP error mapping. Store ports
//! own transactions; this boundary never treats a cached role as commit authority.

use super::*;
use fleet_application::admin_identity::{AdminMutationPrincipal, AdminOperation};
use fleet_application::{
    AdminCommandCommitError, AdminCommandJobRepository, CommandCreationMetadata,
    CreateAuthorizedCommandJobError, PreparedCommandJob,
};

impl fleet_application::admin_remediation::AdminRemediationRead for ControllerStoreRef<'_> {
    fn remediation_for_action(
        &self,
        id: &str,
    ) -> Result<
        Option<fleet_application::RemediationRequestRecord>,
        fleet_application::admin_identity::AdminAccessError,
    > {
        use fleet_application::admin_remediation::AdminRemediationRead;
        match self {
            Self::Sqlite(store) => AdminRemediationRead::remediation_for_action(*store, id),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => AdminRemediationRead::remediation_for_action(
                &*store.try_borrow().map_err(|_| {
                    fleet_application::admin_identity::AdminAccessError::Unavailable
                })?,
                id,
            ),
        }
    }
    fn approval_for_remediation_action(
        &self,
        id: &str,
    ) -> Result<
        Option<fleet_application::ApprovalRequestRecord>,
        fleet_application::admin_identity::AdminAccessError,
    > {
        use fleet_application::admin_remediation::AdminRemediationRead;
        match self {
            Self::Sqlite(store) => {
                AdminRemediationRead::approval_for_remediation_action(*store, id)
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => AdminRemediationRead::approval_for_remediation_action(
                &*store.try_borrow().map_err(|_| {
                    fleet_application::admin_identity::AdminAccessError::Unavailable
                })?,
                id,
            ),
        }
    }
}

pub(super) fn remediation_error<S>(
    error: fleet_application::admin_remediation::AdminRemediationError<S>,
) -> RemediationHttpError {
    use fleet_application::admin_remediation::AdminRemediationError;
    match error {
        AdminRemediationError::Access(
            fleet_application::admin_identity::AdminAccessError::NotFound,
        ) => RemediationHttpError::NotFound,
        AdminRemediationError::Access(error) => RemediationHttpError::Authorization(error),
        AdminRemediationError::Invalid(message) => RemediationHttpError::BadRequest(message),
        AdminRemediationError::Sign(_) => RemediationHttpError::Internal(ControllerError::Json(
            "remediation_signing_unavailable".to_owned(),
        )),
    }
}

impl fleet_application::AdminCatalogJobRepository for ControllerStore {
    fn commit_admin_catalog_job(
        &mut self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: fleet_application::CatalogRunbookJobCreation<'_>,
    ) -> Result<
        fleet_application::CatalogRunbookJobCreationOutcome,
        fleet_application::AdminJobCommitError<fleet_store::StoreError>,
    > {
        match self {
            Self::Sqlite(store) => {
                store.commit_admin_catalog_job_record(principal, operation, creation)
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store
                .try_borrow_mut()
                .map_err(|_| {
                    fleet_application::AdminJobCommitError::Authorization(
                        fleet_application::admin_identity::AdminAccessError::Unavailable,
                    )
                })?
                .commit_admin_catalog_job_record(principal, operation, creation),
        }
    }
}

impl AdminCommandJobRepository for ControllerStoreRef<'_> {
    type Error = fleet_store::StoreError;
    fn commit_admin_command_job(
        &mut self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: &PreparedCommandJob,
        metadata: &CommandCreationMetadata,
    ) -> Result<(), AdminCommandCommitError<Self::Error>> {
        match self {
            Self::Sqlite(store) => {
                store.commit_admin_command_record(principal, operation, creation, metadata)
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store
                .try_borrow_mut()
                .map_err(|_| {
                    AdminCommandCommitError::Authorization(
                        fleet_application::admin_identity::AdminAccessError::Unavailable,
                    )
                })?
                .commit_admin_command_record(principal, operation, creation, metadata),
        }
    }
}

pub(super) fn command_error(
    error: CreateAuthorizedCommandJobError<fleet_store::StoreError, fleet_core::IdentityError>,
) -> CreateCommandJobHttpError {
    match error {
        CreateAuthorizedCommandJobError::Operation(error)
        | CreateAuthorizedCommandJobError::Commit(AdminCommandCommitError::Authorization(error)) => {
            CreateCommandJobHttpError::Authorization(error)
        }
        CreateAuthorizedCommandJobError::Commit(AdminCommandCommitError::DuplicateJob) => {
            CreateCommandJobHttpError::Conflict("job_already_exists".to_owned())
        }
        CreateAuthorizedCommandJobError::Commit(AdminCommandCommitError::Repository(_)) => {
            CreateCommandJobHttpError::Internal(ControllerError::Json(
                "command_job_creation_unavailable".to_owned(),
            ))
        }
        CreateAuthorizedCommandJobError::Preparation(error) => {
            map_create_command_job_error(match error {
                CreateCommandJobError::Domain(error) => CreateCommandJobError::Domain(error),
                CreateCommandJobError::Agent(error) => CreateCommandJobError::Agent(error),
                CreateCommandJobError::NoTargets => CreateCommandJobError::NoTargets,
                CreateCommandJobError::Sign(_) => {
                    return CreateCommandJobHttpError::Internal(ControllerError::Json(
                        "command_job_creation_unavailable".to_owned(),
                    ));
                }
                CreateCommandJobError::Repository(never) | CreateCommandJobError::Audit(never) => {
                    match never {}
                }
            })
        }
    }
}

impl fleet_application::admin_approval::AdminApprovalRepository for ControllerStoreRef<'_> {
    fn approval_transaction<T>(
        &mut self,
        work: impl FnOnce(
            &mut dyn fleet_application::admin_approval::AdminApprovalTransaction,
        ) -> Result<T, fleet_application::admin_approval::AdminApprovalError>,
    ) -> Result<T, fleet_application::admin_approval::AdminApprovalError> {
        match self {
            Self::Sqlite(store) => {
                fleet_application::admin_approval::AdminApprovalRepository::approval_transaction(
                    &mut &**store,
                    work,
                )
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => {
                fleet_application::admin_approval::AdminApprovalRepository::approval_transaction(
                    &mut *store.try_borrow_mut().map_err(|_| {
                        fleet_application::admin_approval::AdminApprovalError::Access(
                            fleet_application::admin_identity::AdminAccessError::Unavailable,
                        )
                    })?,
                    work,
                )
            }
        }
    }
}

pub(super) fn approval_error(
    error: fleet_application::admin_approval::AdminApprovalError,
) -> CreateCommandJobHttpError {
    match error {
        fleet_application::admin_approval::AdminApprovalError::Access(error) => {
            CreateCommandJobHttpError::Authorization(error)
        }
        fleet_application::admin_approval::AdminApprovalError::Domain(error) => {
            CreateCommandJobHttpError::BadRequest(error.to_string())
        }
    }
}

impl fleet_application::AdminStructuredJobRepository for ControllerStoreRef<'_> {
    type Error = fleet_store::StoreError;
    fn commit_admin_structured_job(
        &mut self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: &fleet_application::PreparedStructuredJob,
        metadata: &fleet_application::JobCreationMetadata,
    ) -> Result<(), fleet_application::AdminJobCommitError<Self::Error>> {
        match self {
            Self::Sqlite(store) => {
                store.commit_admin_structured_job_record(principal, operation, creation, metadata)
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store
                .try_borrow_mut()
                .map_err(|_| {
                    fleet_application::AdminJobCommitError::Authorization(
                        fleet_application::admin_identity::AdminAccessError::Unavailable,
                    )
                })?
                .commit_admin_structured_job_record(principal, operation, creation, metadata),
        }
    }
}
pub(super) fn structured_error(
    error: fleet_application::AdminStructuredJobError<
        fleet_store::StoreError,
        fleet_core::IdentityError,
    >,
) -> CreateCommandJobHttpError {
    use fleet_application::{AdminJobCommitError, AdminStructuredJobError};
    match error {
        AdminStructuredJobError::Operation(error)
        | AdminStructuredJobError::Commit(AdminJobCommitError::Authorization(error)) => {
            CreateCommandJobHttpError::Authorization(error)
        }
        AdminStructuredJobError::Commit(AdminJobCommitError::DuplicateJob) => {
            CreateCommandJobHttpError::Conflict("job_already_exists".to_owned())
        }
        AdminStructuredJobError::Commit(AdminJobCommitError::Repository(_)) => {
            unavailable_structured()
        }
        AdminStructuredJobError::Drift(error) => match error {
            CreateDriftCheckJobError::Domain(error) => {
                CreateCommandJobHttpError::BadRequest(error.to_string())
            }
            CreateDriftCheckJobError::Agent(error) => {
                CreateCommandJobHttpError::BadRequest(error.to_string())
            }
            CreateDriftCheckJobError::NoTargets => CreateCommandJobHttpError::BadRequest(
                "drift check job requires at least one target".to_owned(),
            ),
            CreateDriftCheckJobError::Sign(_) => unavailable_structured(),
            CreateDriftCheckJobError::Repository(never)
            | CreateDriftCheckJobError::Audit(never) => match never {},
        },
        AdminStructuredJobError::Runbook(error) => match error {
            CreateRunbookJobError::Domain(error) => {
                CreateCommandJobHttpError::BadRequest(error.to_string())
            }
            CreateRunbookJobError::Agent(error) => {
                CreateCommandJobHttpError::BadRequest(error.to_string())
            }
            CreateRunbookJobError::InvalidRunbook(error) => {
                CreateCommandJobHttpError::BadRequest(error)
            }
            CreateRunbookJobError::NoTargets => CreateCommandJobHttpError::BadRequest(
                "runbook job requires at least one target".to_owned(),
            ),
            CreateRunbookJobError::Sign(_) => unavailable_structured(),
            CreateRunbookJobError::Repository(never) | CreateRunbookJobError::Audit(never) => {
                match never {}
            }
        },
    }
}
fn unavailable_structured() -> CreateCommandJobHttpError {
    CreateCommandJobHttpError::Internal(ControllerError::Json(
        "structured_job_creation_unavailable".to_owned(),
    ))
}

impl fleet_application::admin_cancel::AdminCancellationRepository for ControllerStoreRef<'_> {
    fn cancellation_transaction<T>(
        &mut self,
        work: impl FnOnce(
            &mut dyn fleet_application::admin_cancel::AdminCancellationTransaction,
        ) -> Result<T, fleet_application::admin_identity::AdminAccessError>,
    ) -> Result<T, fleet_application::admin_identity::AdminAccessError> {
        match self {
            Self::Sqlite(store) => fleet_application::admin_cancel::AdminCancellationRepository::cancellation_transaction(&mut &**store,work),
            #[cfg(feature="postgres")]
            Self::Postgres(store) => fleet_application::admin_cancel::AdminCancellationRepository::cancellation_transaction(&mut *store.try_borrow_mut().map_err(|_|fleet_application::admin_identity::AdminAccessError::Unavailable)?,work),
        }
    }
}
