//! Owner-only account metadata reads. Repository pages carry validated Domain accounts;
//! only explicit summaries cross this use-case boundary, without verifiers or credentials.

use super::*;

pub trait AdminAccountQuery: AdminIdentityRead {
    /// Strictly increasing immutable IDs after an exclusive position. The adapter must
    /// apply the 1..=101 bound in its single query, including at most one lookahead row.
    fn account_page(
        &self,
        after: Option<&AdminUserId>,
        limit: usize,
    ) -> Result<Vec<AdminAccount>, AdminAccessError>;
}

#[derive(Debug)]
pub struct AdminAccountMetadataPage {
    pub items: Vec<AdminAccountSummary>,
    pub next_after: Option<AdminUserId>,
}

pub struct ListAdminAccountMetadataInput<'a> {
    pub after: Option<&'a AdminUserId>,
    pub limit: AdminMetadataPageSize,
}

pub struct ListAdminAccountMetadata;
impl ListAdminAccountMetadata {
    /// Rejects non-owners before querying and rechecks current identity after the bounded
    /// read. Invalid order, lookahead or bounds fail closed; this never cleans or renews.
    pub fn execute<R: AdminAccountQuery + ?Sized>(
        repository: &R,
        actor: &AuthenticatedAdmin,
        operation: &dyn AdminOperation,
        input: ListAdminAccountMetadataInput<'_>,
    ) -> Result<AdminAccountMetadataPage, AdminAccessError> {
        let began = checked_now(operation)?;
        authorize_current(repository, actor, AdminPermission::AccountManage, began)?;
        let mut rows = repository.account_page(input.after, input.limit.get() + 1)?;
        if rows.len() > input.limit.get() + 1
            || rows
                .windows(2)
                .any(|pair| pair[0].snapshot().id >= pair[1].snapshot().id)
            || rows.iter().any(|account| {
                input
                    .after
                    .is_some_and(|position| &account.snapshot().id <= position)
            })
        {
            return Err(AdminAccessError::Unavailable);
        }
        let now = auth::checked_auth_now(operation, began)?;
        authorize_current(repository, actor, AdminPermission::AccountManage, now)?;
        let has_more = rows.len() > input.limit.get();
        rows.truncate(input.limit.get());
        let next_after = if has_more {
            rows.last().map(|account| account.snapshot().id)
        } else {
            None
        };
        Ok(AdminAccountMetadataPage {
            items: rows.iter().map(AdminAccountSummary::from).collect(),
            next_after,
        })
    }
}

pub struct GetAdminAccountMetadata;
impl GetAdminAccountMetadata {
    /// Existence is visible only to a current owner. Authority is checked both before the
    /// lookup and before returning its metadata or NotFound result.
    pub fn execute<R: AdminIdentityRead + ?Sized>(
        repository: &R,
        actor: &AuthenticatedAdmin,
        operation: &dyn AdminOperation,
        id: &AdminUserId,
    ) -> Result<AdminAccountSummary, AdminAccessError> {
        let began = checked_now(operation)?;
        authorize_current(repository, actor, AdminPermission::AccountManage, began)?;
        let account = repository.account_by_id(id)?;
        let now = auth::checked_auth_now(operation, began)?;
        authorize_current(repository, actor, AdminPermission::AccountManage, now)?;
        account
            .as_ref()
            .map(AdminAccountSummary::from)
            .ok_or(AdminAccessError::NotFound)
    }
}
