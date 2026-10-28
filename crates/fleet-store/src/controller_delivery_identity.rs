//! Bootstrap-generated Controller delivery identity, separate from signing keys.
//! A namespace survives reopen/restore; explicit restore rotates the store epoch.

use crate::{SqliteStore, StoreError};
use fleet_application::delivery::{
    ControllerDeliveryIdentity, ControllerDeliveryIdentityRepository,
};
use rusqlite::{OptionalExtension, params};

fn fresh_id() -> Result<String, StoreError> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| {
        StoreError::Domain("controller delivery identity entropy unavailable".into())
    })?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn validate(row: (String, String)) -> Result<ControllerDeliveryIdentity, StoreError> {
    for value in [&row.0, &row.1] {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StoreError::Domain(
                "controller delivery identity is invalid".into(),
            ));
        }
    }
    Ok(ControllerDeliveryIdentity {
        namespace: row.0,
        store_epoch: row.1,
    })
}

fn load_sqlite(store: &SqliteStore) -> Result<Option<ControllerDeliveryIdentity>, StoreError> {
    let row: Option<(String, String)> = store
        .connection
        .query_row(
            "SELECT namespace, store_epoch FROM controller_delivery_identity WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(validate).transpose()
}

pub(super) fn ensure_sqlite(store: &SqliteStore) -> Result<(), StoreError> {
    if load_sqlite(store)?.is_none() {
        let namespace = fresh_id()?;
        let store_epoch = fresh_id()?;
        store.connection.execute(
            "INSERT OR IGNORE INTO controller_delivery_identity (id, namespace, store_epoch)
             VALUES (1, ?1, ?2)",
            params![namespace, store_epoch],
        )?;
    }
    load_sqlite(store)?.ok_or(StoreError::NotFound)?;
    Ok(())
}

impl ControllerDeliveryIdentityRepository for SqliteStore {
    type Error = StoreError;

    fn controller_delivery_identity(&self) -> Result<ControllerDeliveryIdentity, Self::Error> {
        load_sqlite(self)?.ok_or(StoreError::NotFound)
    }

    fn rotate_controller_store_epoch(&mut self) -> Result<ControllerDeliveryIdentity, Self::Error> {
        let new_epoch = fresh_id()?;
        let changed = self.connection.execute(
            "UPDATE controller_delivery_identity SET store_epoch = ?1 WHERE id = 1",
            params![new_epoch],
        )?;
        if changed != 1 {
            return Err(StoreError::NotFound);
        }
        self.controller_delivery_identity()
    }
}

#[cfg(feature = "postgres")]
fn load_postgres(
    client: &mut postgres::Client,
) -> Result<Option<ControllerDeliveryIdentity>, StoreError> {
    let row = client
        .query_opt(
            "SELECT namespace, store_epoch FROM controller_delivery_identity WHERE id = 1",
            &[],
        )
        .map_err(|_| StoreError::Postgres("postgres delivery identity read failed".into()))?;
    row.map(|row| validate((row.get(0), row.get(1))))
        .transpose()
}

#[cfg(feature = "postgres")]
pub(super) fn ensure_postgres(client: &mut postgres::Client) -> Result<(), StoreError> {
    if load_postgres(client)?.is_none() {
        let namespace = fresh_id()?;
        let store_epoch = fresh_id()?;
        client
            .execute(
                "INSERT INTO controller_delivery_identity (id, namespace, store_epoch)
                 VALUES (1, $1, $2) ON CONFLICT (id) DO NOTHING",
                &[&namespace, &store_epoch],
            )
            .map_err(|_| StoreError::Postgres("postgres delivery identity insert failed".into()))?;
    }
    load_postgres(client)?.ok_or(StoreError::NotFound)?;
    Ok(())
}

#[cfg(feature = "postgres")]
impl ControllerDeliveryIdentityRepository for crate::PostgresStore {
    type Error = StoreError;

    fn controller_delivery_identity(&self) -> Result<ControllerDeliveryIdentity, Self::Error> {
        let mut client = self.checkout_client()?;
        load_postgres(&mut client)?.ok_or(StoreError::NotFound)
    }

    fn rotate_controller_store_epoch(&mut self) -> Result<ControllerDeliveryIdentity, Self::Error> {
        let new_epoch = fresh_id()?;
        let mut client = self.checkout_client()?;
        let changed = client
            .execute(
                "UPDATE controller_delivery_identity SET store_epoch = $1 WHERE id = 1",
                &[&new_epoch],
            )
            .map_err(|_| StoreError::Postgres("postgres delivery epoch rotation failed".into()))?;
        if changed != 1 {
            return Err(StoreError::NotFound);
        }
        load_postgres(&mut client)?.ok_or(StoreError::NotFound)
    }
}
