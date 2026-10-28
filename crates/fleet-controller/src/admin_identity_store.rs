//! Short-lived access to the Controller-owned identity store. Password/entropy work never
//! owns this mutex; Application callbacks alone own canonical write transactions.

use super::{ControllerStore, ControllerStoreRef};
use fleet_application::admin_identity::*;
use fleet_domain::{
    AdminAccount, AdminCredential, AdminCredentialDigest, AdminCredentialId, AdminCredentialKind,
    AdminUserId, AdminUsername,
};
use std::sync::{Arc, Mutex};

macro_rules! identity_reads {
    ($($name:ident($($arg:ident: $type:ty),*) -> $result:ty;)+) => {
        impl AdminIdentityRead for ControllerStoreRef<'_> {
            $(fn $name(&self, $($arg: $type),*) -> Result<$result, AdminAccessError> {
                match self {
                    Self::Sqlite(store) => store.$name($($arg),*),
                    #[cfg(feature = "postgres")]
                    Self::Postgres(store) => store.try_borrow()
                        .map_err(|_| AdminAccessError::Unavailable)?.$name($($arg),*),
                }
            })+
        }
        impl AdminIdentityRead for SharedIdentityRepository {
            $(fn $name(&self, $($arg: $type),*) -> Result<$result, AdminAccessError> {
                let store = self.0.lock().map_err(|_| AdminAccessError::Unavailable)?;
                ControllerStoreRef::from(&*store).$name($($arg),*)
            })+
        }
    }
}

identity_reads! {
    own_personal_token(owner: &AdminUserId, id: &AdminCredentialId) -> Option<AdminCredential>;
    auth_state() -> AdminAuthState;
    account_by_id(id: &AdminUserId) -> Option<AdminAccount>;
    account_by_username(username: &AdminUsername) -> Option<AdminAccount>;
    loginable_owner_count() -> usize;
    credential_by_id(id: &AdminCredentialId) -> Option<AdminCredential>;
    credential_by_digest(kind: AdminCredentialKind, digest: &AdminCredentialDigest) -> Option<AdminCredential>;
}

pub(super) struct SharedIdentityRepository(pub(super) Arc<Mutex<ControllerStore>>);

impl AdminAccountQuery for ControllerStoreRef<'_> {
    fn account_page(
        &self,
        after: Option<&AdminUserId>,
        limit: usize,
    ) -> Result<Vec<AdminAccount>, AdminAccessError> {
        match self {
            Self::Sqlite(store) => store.account_page(after, limit),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store
                .try_borrow()
                .map_err(|_| AdminAccessError::Unavailable)?
                .account_page(after, limit),
        }
    }
}

impl AdminAccountQuery for SharedIdentityRepository {
    fn account_page(
        &self,
        after: Option<&AdminUserId>,
        limit: usize,
    ) -> Result<Vec<AdminAccount>, AdminAccessError> {
        let store = self.0.lock().map_err(|_| AdminAccessError::Unavailable)?;
        ControllerStoreRef::from(&*store).account_page(after, limit)
    }
}

impl AdminPersonalTokenQuery for ControllerStoreRef<'_> {
    fn personal_token_page(
        &self,
        owner: &AdminUserId,
        after: Option<&AdminCredentialId>,
        limit: usize,
    ) -> Result<Vec<AdminCredential>, AdminAccessError> {
        match self {
            Self::Sqlite(store) => store.personal_token_page(owner, after, limit),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store
                .try_borrow()
                .map_err(|_| AdminAccessError::Unavailable)?
                .personal_token_page(owner, after, limit),
        }
    }
}

impl AdminPersonalTokenQuery for SharedIdentityRepository {
    fn personal_token_page(
        &self,
        owner: &AdminUserId,
        after: Option<&AdminCredentialId>,
        limit: usize,
    ) -> Result<Vec<AdminCredential>, AdminAccessError> {
        let store = self.0.lock().map_err(|_| AdminAccessError::Unavailable)?;
        ControllerStoreRef::from(&*store).personal_token_page(owner, after, limit)
    }
}

impl AdminIdentityRepository for SharedIdentityRepository {
    fn identity_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminIdentityTransaction) -> Result<T, AdminAccessError>,
    ) -> Result<T, AdminAccessError> {
        let mut store = self.0.lock().map_err(|_| AdminAccessError::Unavailable)?;
        match &mut *store {
            ControllerStore::Sqlite(store) => store.identity_transaction(work),
            #[cfg(feature = "postgres")]
            ControllerStore::Postgres(store) => store
                .try_borrow_mut()
                .map_err(|_| AdminAccessError::Unavailable)?
                .identity_transaction(work),
        }
    }
}

pub(super) fn cleanup_bootstrap(store: &mut ControllerStore) -> Result<usize, AdminAccessError> {
    let owner = crate::admin_password_worker::AdminAuthRequest::new(
        crate::admin_crypto::AdminAuthSettings::new(1)?,
    )?;
    let operation = owner.operation();
    match store {
        ControllerStore::Sqlite(store) => CleanupAdminCredentialLookups::execute(store, &operation),
        #[cfg(feature = "postgres")]
        ControllerStore::Postgres(store) => CleanupAdminCredentialLookups::execute(
            &mut *store
                .try_borrow_mut()
                .map_err(|_| AdminAccessError::Unavailable)?,
            &operation,
        ),
    }
}
