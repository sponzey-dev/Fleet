//! Human-authorized catalog execution reuses the existing immutable preparation
//! flow and requires a protected composite commit; it cannot fall back to trusted writes.

use crate::admin_identity::{AdminMutationPrincipal, AdminOperation, OrderedAdminOperation};
use crate::*;

/// Extends the narrow execution read view with an atomic authority-aware commit.
/// Implementations retain the existing catalog binding check and every creation effect.
pub trait AdminCatalogJobRepository: CatalogJobCreationRead {
    fn commit_admin_catalog_job(
        &mut self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: CatalogRunbookJobCreation<'_>,
    ) -> Result<CatalogRunbookJobCreationOutcome, AdminJobCommitError<Self::Error>>;
}

pub type AuthorizedCatalogJobError<R, S> = CreateCatalogRunbookJobError<AdminJobCommitError<R>, S>;

struct AuthorizedCatalog<'a, R> {
    repository: &'a mut R,
    principal: &'a AdminMutationPrincipal,
    operation: &'a dyn AdminOperation,
}
impl<R: AdminCatalogJobRepository> CatalogJobCreationRead for AuthorizedCatalog<'_, R> {
    type Error = AdminJobCommitError<R::Error>;
    fn execution_source(&self, id: &CatalogSourceId) -> Result<Option<CatalogSource>, Self::Error> {
        self.repository
            .execution_source(id)
            .map_err(AdminJobCommitError::Repository)
    }
    fn execution_revision(
        &self,
        id: &CatalogSourceId,
        commit: &CatalogCommitId,
    ) -> Result<Option<CatalogRevision>, Self::Error> {
        self.repository
            .execution_revision(id, commit)
            .map_err(AdminJobCommitError::Repository)
    }
    fn execution_document(
        &self,
        id: &CatalogSourceId,
        commit: &CatalogCommitId,
        path: &str,
    ) -> Result<Option<CatalogDocumentRecord>, Self::Error> {
        self.repository
            .execution_document(id, commit, path)
            .map_err(AdminJobCommitError::Repository)
    }
}
impl<R: AdminCatalogJobRepository> CatalogRunbookJobCreationRepository
    for AuthorizedCatalog<'_, R>
{
    fn commit_catalog_runbook_job(
        &mut self,
        creation: CatalogRunbookJobCreation<'_>,
    ) -> Result<CatalogRunbookJobCreationOutcome, Self::Error> {
        self.repository
            .commit_admin_catalog_job(self.principal, self.operation, creation)
    }
}

pub struct CreateAuthorizedCatalogRunbookJob;
impl CreateAuthorizedCatalogRunbookJob {
    /// Derives all human actors from the authenticated principal. Signing and catalog
    /// reads precede the required canonical authority/catalog transaction.
    pub fn execute<R: AdminCatalogJobRepository, S: TaskEnvelopeSigner>(
        repository: &mut R,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        signer: &mut S,
        mut input: CreateCatalogRunbookJobInput,
    ) -> Result<CreateRunbookJobOutput, AuthorizedCatalogJobError<R::Error, S::Error>> {
        let operation = OrderedAdminOperation::new(operation);
        operation.checked_now().map_err(|error| {
            CreateCatalogRunbookJobError::Repository(AdminJobCommitError::Authorization(error))
        })?;
        input.confirmed_by = principal.actor_id().to_owned();
        CreateCatalogRunbookJob::execute(
            &mut AuthorizedCatalog {
                repository,
                principal,
                operation: &operation,
            },
            signer,
            input,
        )
    }
}
