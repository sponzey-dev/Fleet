use super::*;
use fleet_domain::*;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

#[path = "admin_auth_tests.rs"]
mod auth;
#[path = "admin_restore_tests.rs"]
mod restore;

#[path = "admin_write_tests.rs"]
mod write;

#[derive(Clone, Debug, PartialEq, Eq)]
struct MemoryData {
    legacy_admin: Option<(String, crate::AdminTokenRecord)>,
    auth: AdminAuthState,
    accounts: BTreeMap<AdminUserId, AdminAccountSnapshot>,
    credentials: BTreeMap<AdminCredentialId, AdminCredentialSnapshot>,
    revoked_users: Vec<AdminUserId>,
    audit: Vec<AuditEvent>,
}

type Race = Box<dyn FnOnce(&mut MemoryData)>;

struct MemoryRepository {
    data: MemoryData,
    fail_audit: bool,
    race: Option<Race>,
    locked: Rc<Cell<bool>>,
    query_override: Option<Vec<AdminCredential>>,
    credential_entropy: Rc<Cell<u128>>,
    account_query_override: Option<Vec<AdminAccount>>,
    account_query_calls: Cell<usize>,
    revoked_after_account_page: bool,
}

impl MemoryRepository {
    fn new() -> Self {
        Self {
            data: MemoryData {
                legacy_admin: None,
                auth: AdminAuthState {
                    mode: AdminAuthMode::LegacyBootstrap,
                    epoch: HumanAuthEpoch::from_bytes([3; 16]),
                },
                accounts: BTreeMap::new(),
                credentials: BTreeMap::new(),
                revoked_users: vec![],
                audit: vec![],
            },
            fail_audit: false,
            race: None,
            locked: Rc::new(Cell::new(false)),
            query_override: None,
            credential_entropy: Rc::new(Cell::new(0)),
            account_query_override: None,
            account_query_calls: Cell::new(0),
            revoked_after_account_page: false,
        }
    }
}

impl AdminWriteRead for MemoryRepository {
    fn legacy_admin_by_hash(
        &self,
        digest: &str,
    ) -> Result<Option<crate::AdminTokenRecord>, AdminAccessError> {
        Ok(self
            .data
            .legacy_admin
            .as_ref()
            .filter(|(key, _)| key == digest)
            .map(|(_, record)| record.clone()))
    }
}

impl AdminIdentityRead for MemoryRepository {
    fn own_personal_token(
        &self,
        owner: &AdminUserId,
        id: &AdminCredentialId,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        self.data
            .credentials
            .get(id)
            .filter(|value| {
                value.kind == AdminCredentialKind::PersonalToken && &value.binding.user_id == owner
            })
            .cloned()
            .map(AdminCredential::from_snapshot)
            .transpose()
            .map_err(|_| AdminAccessError::Unavailable)
    }
    fn auth_state(&self) -> Result<AdminAuthState, AdminAccessError> {
        Ok(self.data.auth)
    }

    fn account_by_id(&self, id: &AdminUserId) -> Result<Option<AdminAccount>, AdminAccessError> {
        self.data
            .accounts
            .get(id)
            .cloned()
            .map(AdminAccount::from_snapshot)
            .transpose()
            .map_err(Into::into)
    }

    fn account_by_username(
        &self,
        username: &AdminUsername,
    ) -> Result<Option<AdminAccount>, AdminAccessError> {
        self.data
            .accounts
            .values()
            .find(|value| &value.username == username)
            .cloned()
            .map(AdminAccount::from_snapshot)
            .transpose()
            .map_err(Into::into)
    }

    fn loginable_owner_count(&self) -> Result<usize, AdminAccessError> {
        Ok(self
            .data
            .accounts
            .values()
            .filter(|value| {
                value.role == AdminRole::Owner
                    && value.status == AdminAccountStatus::Active
                    && value.password_verifier.is_some()
            })
            .count())
    }

    fn credential_by_id(
        &self,
        id: &AdminCredentialId,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        if self.revoked_after_account_page && self.account_query_calls.get() > 0 {
            return Ok(None);
        }
        self.data
            .credentials
            .get(id)
            .cloned()
            .map(AdminCredential::from_snapshot)
            .transpose()
            .map_err(|_| AdminAccessError::Unavailable)
    }

    fn credential_by_digest(
        &self,
        kind: AdminCredentialKind,
        digest: &AdminCredentialDigest,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        self.data
            .credentials
            .values()
            .find(|value| value.kind == kind && &value.digest == digest)
            .cloned()
            .map(AdminCredential::from_snapshot)
            .transpose()
            .map_err(|_| AdminAccessError::Unavailable)
    }
}

impl AdminAccountQuery for MemoryRepository {
    fn account_page(
        &self,
        after: Option<&AdminUserId>,
        limit: usize,
    ) -> Result<Vec<AdminAccount>, AdminAccessError> {
        if !(1..=101).contains(&limit) {
            return Err(AdminAccessError::InvalidRequest);
        }
        self.account_query_calls
            .set(self.account_query_calls.get() + 1);
        if let Some(rows) = &self.account_query_override {
            return Ok(rows.clone());
        }
        self.data
            .accounts
            .values()
            .filter(|row| after.is_none_or(|position| &row.id > position))
            .take(limit)
            .cloned()
            .map(AdminAccount::from_snapshot)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

impl AdminPersonalTokenQuery for MemoryRepository {
    fn personal_token_page(
        &self,
        owner: &AdminUserId,
        after: Option<&AdminCredentialId>,
        limit: usize,
    ) -> Result<Vec<AdminCredential>, AdminAccessError> {
        if !(1..=101).contains(&limit) {
            return Err(AdminAccessError::InvalidRequest);
        }
        if let Some(rows) = &self.query_override {
            return Ok(rows.clone());
        }
        self.data
            .credentials
            .values()
            .filter(|value| {
                value.kind == AdminCredentialKind::PersonalToken
                    && &value.binding.user_id == owner
                    && after.is_none_or(|position| &value.id > position)
            })
            .take(limit)
            .cloned()
            .map(|value| {
                AdminCredential::from_snapshot(value).map_err(|_| AdminAccessError::Unavailable)
            })
            .collect()
    }
}

impl AdminIdentityTransaction for MemoryRepository {
    fn credential_counts(
        &self,
        kind: AdminCredentialKind,
        user: &AdminUserId,
        now: i64,
    ) -> Result<AdminCredentialCounts, AdminAccessError> {
        if kind.is_grant() || now < 0 {
            return Err(AdminAccessError::InvalidRequest);
        }
        let state = self.auth_state()?;
        let account = self.account_by_id(user)?;
        let mut result = AdminCredentialCounts {
            valid_for_user: 0,
            total_rows: 0,
        };
        for value in self
            .data
            .credentials
            .values()
            .filter(|value| value.kind == kind)
        {
            result.total_rows += 1;
            if &value.binding.user_id == user {
                let credential = AdminCredential::from_snapshot(value.clone())
                    .map_err(|_| AdminAccessError::Unavailable)?;
                if account.as_ref().is_some_and(|a| {
                    credential
                        .validate(kind, state.mode, a, state.epoch, now)
                        .is_ok()
                }) {
                    result.valid_for_user += 1;
                }
            }
        }
        Ok(result)
    }

    fn cleanup_retired_credentials(
        &mut self,
        kind: AdminCredentialKind,
        now: i64,
        limit: usize,
    ) -> Result<usize, AdminAccessError> {
        if now < 0 || limit == 0 || limit > ADMIN_LOOKUP_CLEANUP_LIMIT {
            return Err(AdminAccessError::InvalidRequest);
        }
        let state = self.auth_state()?;
        let mut retired = Vec::new();
        for value in self
            .data
            .credentials
            .values()
            .filter(|value| value.kind == kind)
        {
            let credential = AdminCredential::from_snapshot(value.clone())
                .map_err(|_| AdminAccessError::Unavailable)?;
            let retired_row = match self.account_by_id(&value.binding.user_id)? {
                None => true,
                Some(account) => {
                    match credential.validate(kind, state.mode, &account, state.epoch, now) {
                        Ok(())
                        | Err(
                            AdminCredentialError::InvalidTime | AdminCredentialError::WrongPurpose,
                        ) => false,
                        Err(_) => true,
                    }
                }
            };
            if retired_row {
                retired.push(value.id.clone());
            }
            if retired.len() == limit {
                break;
            }
        }
        for id in &retired {
            self.data.credentials.remove(id);
        }
        Ok(retired.len())
    }

    fn insert_account(&mut self, value: &AdminAccountSnapshot) -> Result<(), AdminAccessError> {
        if self.data.accounts.contains_key(&value.id)
            || self
                .data
                .accounts
                .values()
                .any(|old| old.username == value.username)
        {
            return Err(AdminAccessError::UserExists);
        }
        self.data.accounts.insert(value.id.clone(), value.clone());
        Ok(())
    }

    fn replace_account(
        &mut self,
        expected: AdminRevision,
        value: &AdminAccountSnapshot,
    ) -> Result<(), AdminAccessError> {
        if self
            .data
            .accounts
            .get(&value.id)
            .map(|old| old.record_revision)
            != Some(expected)
        {
            return Err(AdminAccessError::Conflict);
        }
        self.data.accounts.insert(value.id.clone(), value.clone());
        Ok(())
    }

    fn set_auth_state(
        &mut self,
        expected: AdminAuthState,
        value: AdminAuthState,
    ) -> Result<(), AdminAccessError> {
        if self.data.auth != expected {
            return Err(AdminAccessError::Conflict);
        }
        self.data.auth = value;
        Ok(())
    }

    fn revoke_user_credentials(
        &mut self,
        user: &AdminUserId,
        now: i64,
    ) -> Result<(), AdminAccessError> {
        self.data.revoked_users.push(user.clone());
        for credential in self
            .data
            .credentials
            .values_mut()
            .filter(|value| &value.binding.user_id == user)
        {
            if credential.state == AdminCredentialState::Active {
                credential.state = AdminCredentialState::Revoked;
                credential.ended_at = Some(now);
            }
        }
        Ok(())
    }

    fn insert_credential(
        &mut self,
        credential: &AdminCredentialSnapshot,
    ) -> Result<(), AdminAccessError> {
        if self.data.credentials.contains_key(&credential.id)
            || self
                .data
                .credentials
                .values()
                .any(|old| old.kind == credential.kind && old.digest == credential.digest)
        {
            return Err(AdminAccessError::Conflict);
        }
        self.data
            .credentials
            .insert(credential.id.clone(), credential.clone());
        Ok(())
    }

    fn replace_credential(
        &mut self,
        expected: &AdminCredentialSnapshot,
        value: &AdminCredentialSnapshot,
    ) -> Result<(), AdminAccessError> {
        if self.data.credentials.get(&expected.id) != Some(expected) || expected.id != value.id {
            return Err(AdminAccessError::Conflict);
        }
        self.data
            .credentials
            .insert(value.id.clone(), value.clone());
        Ok(())
    }

    fn append_identity_audit(&mut self, event: &AuditEvent) -> Result<(), AdminAccessError> {
        if self.fail_audit {
            return Err(AdminAccessError::Unavailable);
        }
        self.data.audit.push(event.clone());
        Ok(())
    }
}

impl AdminIdentityRepository for MemoryRepository {
    fn identity_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminIdentityTransaction) -> Result<T, AdminAccessError>,
    ) -> Result<T, AdminAccessError> {
        if let Some(race) = self.race.take() {
            race(&mut self.data);
        }
        let before = self.data.clone();
        self.locked.set(true);
        let result = work(self);
        self.locked.set(false);
        if result.is_err() {
            self.data = before;
        }
        result
    }
}

struct Passwords {
    locked: Rc<Cell<bool>>,
    calls: Cell<usize>,
}

impl AdminPasswordPort for Passwords {
    fn hash_new(
        &self,
        _input: &str,
        _username: &AdminUsername,
    ) -> Result<AdminPasswordVerifier, AdminAccessError> {
        assert!(!self.locked.get(), "KDF must run outside the transaction");
        self.calls.set(self.calls.get() + 1);
        Ok(
            AdminPasswordVerifier::from_parts(
                AdminPasswordVerifier::PROFILE_ID,
                &[4; 16],
                &[5; 32],
            )
            .unwrap(),
        )
    }

    fn verify(
        &self,
        input: &str,
        verifier: Option<&AdminPasswordVerifier>,
    ) -> Result<bool, AdminAccessError> {
        assert!(!self.locked.get(), "KDF must run outside the transaction");
        Ok(input == "fixture current password" && verifier.is_some())
    }
}

struct Generator {
    next: Cell<u128>,
    credential_next: Rc<Cell<u128>>,
}
impl AdminIdentityGenerator for Generator {
    fn user_id(&self) -> Result<AdminUserId, AdminAccessError> {
        let value = self.next.get() + 1;
        self.next.set(value);
        Ok(AdminUserId::parse(format!("usr_{value:032x}")).unwrap())
    }

    fn credential(
        &self,
        kind: AdminCredentialKind,
    ) -> Result<AdminNewCredential, AdminAccessError> {
        let value = self
            .credential_next
            .get()
            .checked_add(1)
            .ok_or(AdminAccessError::Unavailable)?;
        self.credential_next.set(value);
        Ok(AdminNewCredential {
            id: AdminCredentialId::parse(format!("crd_{value:032x}")).unwrap(),
            kind,
            digest: fixture_credential_digest(value),
            secret: AdminSecret::from_adapter(format!("fixture_secret_{value:064x}")).unwrap(),
        })
    }
}

struct Local(bool);
impl AdminLocalAuthority for Local {
    fn require_exclusive(&self) -> Result<AuditActor, AdminAccessError> {
        if self.0 {
            Ok(AuditActor::new("local:fixture"))
        } else {
            Err(AdminAccessError::Forbidden)
        }
    }
}

struct Operation {
    fail: bool,
}
impl AdminOperation for Operation {
    fn checked_now(&self) -> Result<i64, AdminAccessError> {
        if self.fail {
            Err(AdminAccessError::OperationExpired)
        } else {
            Ok(1_000)
        }
    }
}

fn input() -> InitializeOwnerInput<'static> {
    InitializeOwnerInput {
        username: AdminUsername::parse("First.Owner").unwrap(),
        display_name: AdminDisplayName::parse("Fixture owner").unwrap(),
        new_password: "fixture password sentinel never log",
    }
}

fn dependencies(repo: &MemoryRepository) -> (Passwords, Generator) {
    (
        Passwords {
            locked: repo.locked.clone(),
            calls: Cell::new(0),
        },
        Generator {
            next: Cell::new(repo.data.accounts.len() as u128),
            credential_next: credential_sequence(repo),
        },
    )
}

// Entropy is not canonical lookup state and cannot be recycled when cleanup removes a row.
// The real adapter uses CSPRNG material; this deterministic fixture preserves that uniqueness.
fn credential_sequence(repo: &MemoryRepository) -> Rc<Cell<u128>> {
    let stored = repo
        .data
        .credentials
        .keys()
        .map(|id| u128::from_str_radix(&id.as_str()[4..], 16).unwrap())
        .max()
        .unwrap_or(0);
    repo.credential_entropy
        .set(repo.credential_entropy.get().max(stored));
    repo.credential_entropy.clone()
}

fn fixture_credential_digest(value: u128) -> AdminCredentialDigest {
    let mut digest = [0; 32];
    digest[..16].copy_from_slice(&value.to_be_bytes());
    AdminCredentialDigest::from_bytes(digest)
}

fn bootstrap(repo: &mut MemoryRepository) -> Result<AdminAccountSummary, AdminAccessError> {
    let (passwords, ids) = dependencies(repo);
    InitializeAdminOwner::execute(
        repo,
        &Local(true),
        &Operation { fail: false },
        &passwords,
        &ids,
        input(),
    )
}

#[test]
fn owner_metadata_reads_are_bounded_and_preserve_every_canonical_record() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let other = add_active(&mut repo, AdminRole::Viewer);
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let before = repo.data.clone();
    let ordered: Vec<_> = repo.data.accounts.keys().cloned().collect();
    let operation = Operation { fail: false };
    let page = ListAdminAccountMetadata::execute(
        &repo,
        &actor,
        &operation,
        ListAdminAccountMetadataInput {
            after: None,
            limit: AdminMetadataPageSize::new(1).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, ordered[0]);
    assert_eq!(page.next_after, Some(ordered[0].clone()));
    let next = ListAdminAccountMetadata::execute(
        &repo,
        &actor,
        &operation,
        ListAdminAccountMetadataInput {
            after: page.next_after.as_ref(),
            limit: AdminMetadataPageSize::new(1).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(next.items[0].id, ordered[1]);
    assert!(next.next_after.is_none());
    let detail = GetAdminAccountMetadata::execute(&repo, &actor, &operation, &other).unwrap();
    assert_eq!((detail.id, detail.role), (other, AdminRole::Viewer));
    assert_eq!(
        repo.data, before,
        "GET must not clean, renew or write account/credential/audit state"
    );
}

#[test]
fn owner_metadata_reads_reject_all_other_roles_before_query_or_resource_disclosure() {
    for role in [AdminRole::Admin, AdminRole::Operator, AdminRole::Viewer] {
        let mut repo = MemoryRepository::new();
        let owner = bootstrap(&mut repo).unwrap();
        let user = add_active(&mut repo, role);
        let actor = authenticated(&mut repo, &user, AdminCredentialKind::PersonalToken);
        let before = repo.data.clone();
        let operation = Operation { fail: false };
        assert!(matches!(
            ListAdminAccountMetadata::execute(
                &repo,
                &actor,
                &operation,
                ListAdminAccountMetadataInput {
                    after: None,
                    limit: AdminMetadataPageSize::default()
                }
            ),
            Err(AdminAccessError::Forbidden)
        ));
        for target in [
            &owner.id,
            &AdminUserId::parse("usr_ffffffffffffffffffffffffffffffff").unwrap(),
        ] {
            assert_eq!(
                GetAdminAccountMetadata::execute(&repo, &actor, &operation, target),
                Err(AdminAccessError::Forbidden)
            );
        }
        assert_eq!(repo.account_query_calls.get(), 0);
        assert_eq!(repo.data, before);
    }
}

#[test]
fn owner_metadata_page_validates_the_lookahead_order_count_and_exclusive_position() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    add_active(&mut repo, AdminRole::Viewer);
    add_active(&mut repo, AdminRole::Operator);
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let rows: Vec<_> = repo
        .data
        .accounts
        .values()
        .cloned()
        .map(AdminAccount::from_snapshot)
        .collect::<Result<_, _>>()
        .unwrap();
    for bad in [
        vec![rows[0].clone(), rows[0].clone()],
        vec![rows[1].clone(), rows[0].clone()],
        rows.clone(),
    ] {
        repo.account_query_override = Some(bad);
        assert!(matches!(
            ListAdminAccountMetadata::execute(
                &repo,
                &actor,
                &Operation { fail: false },
                ListAdminAccountMetadataInput {
                    after: None,
                    limit: AdminMetadataPageSize::new(1).unwrap()
                }
            ),
            Err(AdminAccessError::Unavailable)
        ));
    }
    repo.account_query_override = Some(vec![rows[0].clone()]);
    assert!(matches!(
        ListAdminAccountMetadata::execute(
            &repo,
            &actor,
            &Operation { fail: false },
            ListAdminAccountMetadataInput {
                after: Some(&rows[0].snapshot().id),
                limit: AdminMetadataPageSize::new(1).unwrap()
            }
        ),
        Err(AdminAccessError::Unavailable)
    ));
}

#[test]
fn owner_metadata_rechecks_revocation_and_clock_after_the_page() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    repo.revoked_after_account_page = true;
    assert!(matches!(
        ListAdminAccountMetadata::execute(
            &repo,
            &actor,
            &Operation { fail: false },
            ListAdminAccountMetadataInput {
                after: None,
                limit: AdminMetadataPageSize::default()
            }
        ),
        Err(AdminAccessError::Unauthorized)
    ));
    repo.revoked_after_account_page = false;
    struct Regressing(Cell<bool>);
    impl AdminOperation for Regressing {
        fn checked_now(&self) -> Result<i64, AdminAccessError> {
            Ok(if self.0.replace(true) { 999 } else { 1000 })
        }
    }
    assert!(matches!(
        ListAdminAccountMetadata::execute(
            &repo,
            &actor,
            &Regressing(Cell::new(false)),
            ListAdminAccountMetadataInput {
                after: None,
                limit: AdminMetadataPageSize::default()
            }
        ),
        Err(AdminAccessError::OperationExpired)
    ));
}

#[test]
fn owner_metadata_missing_resource_and_deadline_fail_without_writes() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let before = repo.data.clone();
    assert_eq!(
        GetAdminAccountMetadata::execute(
            &repo,
            &actor,
            &Operation { fail: false },
            &AdminUserId::parse("usr_ffffffffffffffffffffffffffffffff").unwrap()
        ),
        Err(AdminAccessError::NotFound)
    );
    assert_eq!(
        GetAdminAccountMetadata::execute(&repo, &actor, &Operation { fail: true }, &owner.id),
        Err(AdminAccessError::OperationExpired)
    );
    assert_eq!(repo.data, before);
}

#[test]
fn bootstrap_atomically_switches_mode_preserving_epoch_and_immutable_actor() {
    let mut repo = MemoryRepository::new();
    let epoch = repo.data.auth.epoch;
    let owner = bootstrap(&mut repo).unwrap();
    assert_eq!(owner.username.as_str(), "first.owner");
    assert_eq!(owner.role, AdminRole::Owner);
    assert_eq!(owner.status, AdminAccountStatus::Active);
    assert_eq!(repo.data.auth.mode, AdminAuthMode::Personal);
    assert_eq!(repo.data.auth.epoch, epoch);
    assert_eq!(repo.data.audit.len(), 1);
    assert_eq!(repo.data.audit[0].actor.as_str(), "local:fixture");
    assert_eq!(repo.data.audit[0].target.as_str(), owner.id.as_str());
    assert_eq!(repo.data.audit[0].action, "admin_owner_initialized");
    assert_eq!(repo.data.audit[0].value, AuditValue::Redacted);
    let before = repo.data.clone();
    assert_eq!(
        bootstrap(&mut repo).unwrap_err(),
        AdminAccessError::Conflict
    );
    assert_eq!(repo.data, before);
}

#[test]
fn bootstrap_audit_failure_rolls_back_account_and_cutover() {
    let mut repo = MemoryRepository::new();
    repo.fail_audit = true;
    let before = repo.data.clone();
    assert_eq!(
        bootstrap(&mut repo).unwrap_err(),
        AdminAccessError::Unavailable
    );
    assert_eq!(repo.data, before);
}

#[test]
fn bootstrap_rechecks_mode_and_epoch_after_hashing() {
    for changed_mode in [true, false] {
        let mut repo = MemoryRepository::new();
        repo.race = Some(Box::new(move |data| {
            if changed_mode {
                data.auth.mode = AdminAuthMode::Personal;
            } else {
                data.auth.epoch = HumanAuthEpoch::from_bytes([8; 16]);
            }
        }));
        assert_eq!(
            bootstrap(&mut repo).unwrap_err(),
            AdminAccessError::Conflict
        );
        assert!(repo.data.accounts.is_empty());
        assert!(repo.data.audit.is_empty());
    }
}

#[test]
fn bootstrap_requires_local_authority_and_live_operation_before_kdf() {
    for (local, expired, error) in [
        (false, false, AdminAccessError::Forbidden),
        (true, true, AdminAccessError::OperationExpired),
    ] {
        let mut repo = MemoryRepository::new();
        let (passwords, ids) = dependencies(&repo);
        let before = repo.data.clone();
        assert_eq!(
            InitializeAdminOwner::execute(
                &mut repo,
                &Local(local),
                &Operation { fail: expired },
                &passwords,
                &ids,
                input()
            )
            .unwrap_err(),
            error
        );
        assert_eq!(passwords.calls.get(), 0);
        assert_eq!(repo.data, before);
    }
}

#[test]
fn bootstrap_rechecks_cancel_and_local_authority_before_commit() {
    struct ExpiringOperation(Cell<usize>);
    impl AdminOperation for ExpiringOperation {
        fn checked_now(&self) -> Result<i64, AdminAccessError> {
            self.0.set(self.0.get() + 1);
            if self.0.get() > 1 {
                Err(AdminAccessError::OperationExpired)
            } else {
                Ok(1_000)
            }
        }
    }
    struct LostAuthority(Cell<usize>);
    impl AdminLocalAuthority for LostAuthority {
        fn require_exclusive(&self) -> Result<AuditActor, AdminAccessError> {
            self.0.set(self.0.get() + 1);
            if self.0.get() > 1 {
                Err(AdminAccessError::Forbidden)
            } else {
                Ok(AuditActor::new("local:fixture"))
            }
        }
    }
    let mut repo = MemoryRepository::new();
    let (passwords, ids) = dependencies(&repo);
    let before = repo.data.clone();
    assert_eq!(
        InitializeAdminOwner::execute(
            &mut repo,
            &Local(true),
            &ExpiringOperation(Cell::new(0)),
            &passwords,
            &ids,
            input()
        )
        .unwrap_err(),
        AdminAccessError::OperationExpired
    );
    assert_eq!(repo.data, before);
    assert_eq!(passwords.calls.get(), 1);
    assert_eq!(
        InitializeAdminOwner::execute(
            &mut repo,
            &LostAuthority(Cell::new(0)),
            &Operation { fail: false },
            &passwords,
            &ids,
            input()
        )
        .unwrap_err(),
        AdminAccessError::Forbidden
    );
    assert_eq!(repo.data, before);
}

#[test]
fn bootstrap_unique_name_race_does_not_partially_switch_mode() {
    let mut repo = MemoryRepository::new();
    repo.race = Some(Box::new(|data| {
        let pending = AdminAccount::pending(
            AdminUserId::parse("usr_00000000000000000000000000000002").unwrap(),
            AdminUsername::parse("FIRST.OWNER").unwrap(),
            AdminDisplayName::parse("Concurrent account").unwrap(),
            AdminRole::Viewer,
        )
        .snapshot();
        data.accounts.insert(pending.id.clone(), pending);
    }));
    assert_eq!(
        bootstrap(&mut repo).unwrap_err(),
        AdminAccessError::UserExists
    );
    assert_eq!(repo.data.auth.mode, AdminAuthMode::LegacyBootstrap);
    assert_eq!(repo.data.accounts.len(), 1);
    assert!(repo.data.audit.is_empty());
}

#[test]
fn local_recovery_activates_selected_owner_and_revokes_only_that_person() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let old = repo.data.accounts.get_mut(&owner.id).unwrap();
    old.status = AdminAccountStatus::Disabled;
    old.role = AdminRole::Viewer;
    let previous = old.clone();
    let other = AdminAccount::pending(
        AdminUserId::parse("usr_00000000000000000000000000000002").unwrap(),
        AdminUsername::parse("other.user").unwrap(),
        AdminDisplayName::parse("Other fixture").unwrap(),
        AdminRole::Admin,
    )
    .snapshot();
    repo.data.accounts.insert(other.id.clone(), other.clone());
    repo.data.auth.mode = AdminAuthMode::LocalSetupRequired;
    let (passwords, _) = dependencies(&repo);
    let recovered = RecoverAdminOwner::execute(
        &mut repo,
        &Local(true),
        &Operation { fail: false },
        &passwords,
        RecoverOwnerInput {
            user_id: owner.id.clone(),
            new_password: "new fixture password sentinel",
        },
    )
    .unwrap();
    assert_eq!(recovered.id, owner.id);
    assert_eq!(recovered.role, AdminRole::Owner);
    assert_eq!(recovered.status, AdminAccountStatus::Active);
    assert_eq!(recovered.username, previous.username);
    assert_eq!(repo.data.auth.mode, AdminAuthMode::Personal);
    assert_eq!(repo.data.accounts[&other.id], other);
    assert_eq!(
        repo.data.accounts[&owner.id].credential_revision.value(),
        previous.credential_revision.value() + 1
    );
    assert_eq!(repo.data.revoked_users, vec![owner.id]);
    assert_eq!(
        repo.data.audit.last().unwrap().action,
        "admin_owner_recovered"
    );
}

#[test]
fn local_recovery_audit_failure_and_stale_account_have_no_partial_effect() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let (passwords, _) = dependencies(&repo);
    repo.fail_audit = true;
    let before = repo.data.clone();
    assert_eq!(
        RecoverAdminOwner::execute(
            &mut repo,
            &Local(true),
            &Operation { fail: false },
            &passwords,
            RecoverOwnerInput {
                user_id: owner.id.clone(),
                new_password: "new fixture password sentinel"
            }
        )
        .unwrap_err(),
        AdminAccessError::Unavailable
    );
    assert_eq!(repo.data, before);
    repo.fail_audit = false;
    let id = owner.id.clone();
    repo.race = Some(Box::new(move |data| {
        data.accounts.get_mut(&id).unwrap().record_revision = AdminRevision::new(2).unwrap();
    }));
    assert_eq!(
        RecoverAdminOwner::execute(
            &mut repo,
            &Local(true),
            &Operation { fail: false },
            &passwords,
            RecoverOwnerInput {
                user_id: owner.id,
                new_password: "new fixture password sentinel"
            }
        )
        .unwrap_err(),
        AdminAccessError::Conflict
    );
    assert!(repo.data.revoked_users.is_empty());
    assert_eq!(repo.data.audit.len(), 1);
}

#[test]
fn local_setup_required_restore_can_initialize_without_reviving_legacy_access() {
    let mut repo = MemoryRepository::new();
    repo.data.auth.mode = AdminAuthMode::LocalSetupRequired;
    bootstrap(&mut repo).unwrap();
    assert_eq!(repo.data.auth.mode, AdminAuthMode::Personal);
}

#[test]
fn password_inputs_and_typed_errors_never_format_the_secret() {
    let input = input();
    assert!(!format!("{input:?}").contains("sentinel"));
    let recovery = RecoverOwnerInput {
        user_id: AdminUserId::parse("usr_00000000000000000000000000000001").unwrap(),
        new_password: "fixture sentinel password",
    };
    assert!(!format!("{recovery:?}").contains("sentinel"));
    assert_eq!(
        AdminAccessError::Unavailable.to_string(),
        "administrator identity service unavailable"
    );
}

fn add_active(repo: &mut MemoryRepository, role: AdminRole) -> AdminUserId {
    let next = repo.data.accounts.len() + 1;
    let mut account = AdminAccount::pending(
        AdminUserId::parse(format!("usr_{next:032x}")).unwrap(),
        AdminUsername::parse(format!("fixture_{next}")).unwrap(),
        AdminDisplayName::parse(format!("Fixture {next}")).unwrap(),
        role,
    );
    account
        .install_password(
            AdminPasswordVerifier::from_parts(
                AdminPasswordVerifier::PROFILE_ID,
                &[4; 16],
                &[5; 32],
            )
            .unwrap(),
        )
        .unwrap();
    let snapshot = account.snapshot();
    repo.data
        .accounts
        .insert(snapshot.id.clone(), snapshot.clone());
    snapshot.id
}

fn authenticated(
    repo: &mut MemoryRepository,
    user: &AdminUserId,
    kind: AdminCredentialKind,
) -> AuthenticatedAdmin {
    let sequence = credential_sequence(repo);
    let value = sequence.get().checked_add(1).unwrap();
    sequence.set(value);
    let account = repo.account_by_id(user).unwrap().unwrap();
    let credential = AdminCredential::issue(
        AdminCredentialId::parse(format!("crd_{value:032x}")).unwrap(),
        kind,
        fixture_credential_digest(value),
        AdminCredentialBinding::for_account(&account, repo.data.auth.epoch),
        1_000,
    )
    .unwrap()
    .snapshot();
    repo.data
        .credentials
        .insert(credential.id.clone(), credential.clone());
    AuthenticateAdminCredential::execute(repo, &Operation { fail: false }, kind, &credential.digest)
        .unwrap()
}

fn create_input() -> CreateAdminAccountInput<'static> {
    CreateAdminAccountInput {
        username: AdminUsername::parse("New.Operator").unwrap(),
        display_name: AdminDisplayName::parse("New operator").unwrap(),
        role: AdminRole::Operator,
        current_password: "fixture current password",
    }
}

fn create(
    repo: &mut MemoryRepository,
    actor: &AuthenticatedAdmin,
    input: CreateAdminAccountInput<'_>,
) -> Result<CreatedAdminAccount, AdminAccessError> {
    let (passwords, generator) = dependencies(repo);
    CreateAdminAccount::execute(
        repo,
        actor,
        &Operation { fail: false },
        &passwords,
        &generator,
        input,
    )
}

fn change_input(user_id: AdminUserId) -> ChangeAdminAccountInput<'static> {
    ChangeAdminAccountInput {
        user_id,
        display_name: None,
        role: None,
        disable: false,
        current_password: "fixture current password",
    }
}

fn change(
    repo: &mut MemoryRepository,
    actor: &AuthenticatedAdmin,
    input: ChangeAdminAccountInput<'_>,
) -> Result<AdminAccountSummary, AdminAccessError> {
    let (passwords, _) = dependencies(repo);
    ChangeAdminAccount::execute(repo, actor, &Operation { fail: false }, &passwords, input)
}

#[test]
fn owner_creation_atomically_returns_one_setup_grant_with_server_actor() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let created = create(&mut repo, &actor, create_input()).unwrap();
    assert_eq!(created.account.role, AdminRole::Operator);
    assert_eq!(created.account.status, AdminAccountStatus::PendingSetup);
    assert_eq!(created.account.username.as_str(), "new.operator");
    assert!(
        repo.data.accounts[&created.account.id]
            .password_verifier
            .is_none()
    );
    assert_eq!(created.setup.kind, AdminCredentialKind::SetupGrant);
    assert_eq!(created.setup.expires_at, 1_900);
    assert!(!created.setup.secret.expose_for_delivery().is_empty());
    assert!(!format!("{created:?}").contains("fixture_secret"));
    let stored = &repo.data.credentials[&created.setup.id];
    assert_eq!(stored.binding.user_id, created.account.id);
    assert_eq!(
        repo.data.audit.last().unwrap().actor.as_str(),
        owner.id.as_str()
    );
    assert_eq!(
        repo.data.audit.last().unwrap().action,
        "admin_account_created"
    );
    assert!(
        AuthenticateAdminCredential::execute(
            &repo,
            &Operation { fail: false },
            AdminCredentialKind::SetupGrant,
            &stored.digest
        )
        .is_err()
    );
}

#[test]
fn only_owner_may_create_or_manage_other_accounts() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    for role in [AdminRole::Admin, AdminRole::Operator, AdminRole::Viewer] {
        let user = add_active(&mut repo, role);
        let actor = authenticated(&mut repo, &user, AdminCredentialKind::PersonalToken);
        let before = repo.data.clone();
        assert_eq!(
            create(&mut repo, &actor, create_input()).unwrap_err(),
            AdminAccessError::Forbidden
        );
        let mut input = change_input(owner.id.clone());
        input.display_name = Some(AdminDisplayName::parse("Forbidden replacement").unwrap());
        assert_eq!(
            change(&mut repo, &actor, input).unwrap_err(),
            AdminAccessError::Forbidden
        );
        assert_eq!(repo.data, before);
    }
}

#[test]
fn wrong_password_and_audit_failure_do_not_issue_account_or_grant() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let before = repo.data.clone();
    let mut input = create_input();
    input.current_password = "wrong fixture password";
    assert_eq!(
        create(&mut repo, &actor, input).unwrap_err(),
        AdminAccessError::Unauthorized
    );
    assert_eq!(repo.data, before);
    repo.fail_audit = true;
    assert_eq!(
        create(&mut repo, &actor, create_input()).unwrap_err(),
        AdminAccessError::Unavailable
    );
    assert_eq!(repo.data, before);
}

#[test]
fn management_rechecks_actor_revocation_and_role_revision_at_commit() {
    for revoke in [true, false] {
        let mut repo = MemoryRepository::new();
        let owner = bootstrap(&mut repo).unwrap();
        let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
        let user = owner.id.clone();
        repo.race = Some(Box::new(move |data| {
            if revoke {
                let credential = data.credentials.values_mut().next().unwrap();
                credential.state = AdminCredentialState::Revoked;
                credential.ended_at = Some(1_000);
            } else {
                let mut account =
                    AdminAccount::from_snapshot(data.accounts[&user].clone()).unwrap();
                account.change_role(AdminRole::Admin, 1).unwrap();
                data.accounts.insert(user, account.snapshot());
            }
        }));
        assert_eq!(
            create(&mut repo, &actor, create_input()).unwrap_err(),
            AdminAccessError::Unauthorized
        );
        assert_eq!(repo.data.accounts.len(), 1);
        assert_eq!(repo.data.credentials.len(), 1);
        assert_eq!(repo.data.audit.len(), 1);
    }
}

#[test]
fn owner_metadata_changes_preserve_credentials_but_last_owner_removal_is_rejected() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let mut input = change_input(owner.id.clone());
    input.display_name = Some(AdminDisplayName::parse("Renamed owner").unwrap());
    let renamed = change(&mut repo, &actor, input).unwrap();
    assert_eq!(renamed.record_revision.value(), 2);
    assert!(repo.data.revoked_users.is_empty());
    let before = repo.data.clone();
    for disable in [true, false] {
        let mut input = change_input(owner.id.clone());
        input.disable = disable;
        input.role = Some(AdminRole::Admin);
        assert_eq!(
            change(&mut repo, &actor, input).unwrap_err(),
            AdminAccessError::LastOwner
        );
        assert_eq!(repo.data, before);
    }
    let mut input = change_input(owner.id);
    input.role = Some(AdminRole::Owner);
    change(&mut repo, &actor, input).unwrap();
    assert_eq!(repo.data, before);
}

#[test]
fn role_and_disable_changes_revoke_all_target_credentials_but_preserve_actor() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let target = add_active(&mut repo, AdminRole::Owner);
    let target_actor = authenticated(&mut repo, &target, AdminCredentialKind::PersonalToken);
    let mut input = change_input(target.clone());
    input.role = Some(AdminRole::Viewer);
    change(&mut repo, &actor, input).unwrap();
    assert_eq!(repo.data.revoked_users, vec![target.clone()]);
    assert_eq!(
        create(&mut repo, &target_actor, create_input()).unwrap_err(),
        AdminAccessError::Unauthorized
    );
    let mut input = change_input(target.clone());
    input.disable = true;
    change(&mut repo, &actor, input).unwrap();
    assert_eq!(
        repo.data.accounts[&target].status,
        AdminAccountStatus::Disabled
    );
    let before = repo.data.clone();
    let mut input = change_input(target);
    input.disable = true;
    change(&mut repo, &actor, input).unwrap();
    assert_eq!(repo.data, before);
    assert_eq!(actor.user_id(), &owner.id);
}

#[test]
fn account_update_audit_failure_rolls_back_revision_and_credential_revocation() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let target = add_active(&mut repo, AdminRole::Viewer);
    authenticated(&mut repo, &target, AdminCredentialKind::PersonalToken);
    let before = repo.data.clone();
    repo.fail_audit = true;
    let mut input = change_input(target);
    input.role = Some(AdminRole::Operator);
    assert_eq!(
        change(&mut repo, &actor, input).unwrap_err(),
        AdminAccessError::Unavailable
    );
    assert_eq!(repo.data, before);
}

#[test]
fn authentication_requires_current_purpose_and_expiry_with_no_permission_claim_input() {
    struct At(i64);
    impl AdminOperation for At {
        fn checked_now(&self) -> Result<i64, AdminAccessError> {
            Ok(self.0)
        }
    }
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let credential = repo.data.credentials.values().next().unwrap();
    assert!(
        AuthenticateAdminCredential::execute(
            &repo,
            &At(29_799),
            AdminCredentialKind::WebSession,
            &credential.digest
        )
        .is_ok()
    );
    assert_eq!(
        AuthenticateAdminCredential::execute(
            &repo,
            &At(29_800),
            AdminCredentialKind::WebSession,
            &credential.digest
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
    assert_eq!(
        AuthenticateAdminCredential::execute(
            &repo,
            &At(1_000),
            AdminCredentialKind::PersonalToken,
            &credential.digest
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
    assert_eq!(
        AuthenticateAdminCredential::execute(
            &repo,
            &At(1_000),
            AdminCredentialKind::WebSession,
            &AdminCredentialDigest::from_bytes([99; 32])
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
}

struct At(i64);
impl AdminOperation for At {
    fn checked_now(&self) -> Result<i64, AdminAccessError> {
        Ok(self.0)
    }
}

fn reset(
    repo: &mut MemoryRepository,
    actor: &AuthenticatedAdmin,
    user_id: AdminUserId,
) -> Result<IssuedAdminCredential, AdminAccessError> {
    let (passwords, generator) = dependencies(repo);
    ResetAdminPassword::execute(
        repo,
        actor,
        &Operation { fail: false },
        &passwords,
        &generator,
        ResetAdminPasswordInput {
            user_id,
            current_password: "fixture current password",
        },
    )
}

fn claim(
    repo: &mut MemoryRepository,
    credential: &AdminCredentialSnapshot,
    at: i64,
) -> Result<(), AdminAccessError> {
    let (passwords, _) = dependencies(repo);
    CompleteAdminSetup::execute(
        repo,
        &At(at),
        &passwords,
        CompleteAdminSetupInput {
            kind: credential.kind,
            digest: credential.digest.clone(),
            new_password: "new setup fixture password",
        },
    )
}

#[test]
fn owner_reset_revokes_old_credentials_and_only_the_new_grant_can_activate() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let target = add_active(&mut repo, AdminRole::Viewer);
    let previous = authenticated(&mut repo, &target, AdminCredentialKind::PersonalToken);
    let old_revision = repo.data.accounts[&target].credential_revision;
    let first = reset(&mut repo, &actor, target.clone()).unwrap();
    let old_grant = repo.data.credentials[&first.id].clone();
    assert_eq!(first.kind, AdminCredentialKind::ResetGrant);
    assert_eq!(first.expires_at, 1_900);
    assert_eq!(
        repo.data.accounts[&target].status,
        AdminAccountStatus::PendingSetup
    );
    assert!(repo.data.accounts[&target].password_verifier.is_none());
    assert_eq!(
        repo.data.accounts[&target].credential_revision.value(),
        old_revision.value() + 1
    );
    assert_eq!(
        create(&mut repo, &previous, create_input()).unwrap_err(),
        AdminAccessError::Unauthorized
    );
    let second = reset(&mut repo, &actor, target.clone()).unwrap();
    assert_ne!(second.id, old_grant.id);
    assert_eq!(
        claim(&mut repo, &old_grant, 1_001),
        Err(AdminAccessError::Unauthorized)
    );
    let new_grant = repo.data.credentials[&second.id].clone();
    claim(&mut repo, &new_grant, 1_001).unwrap();
    assert_eq!(
        repo.data.accounts[&target].status,
        AdminAccountStatus::Active
    );
    assert!(!repo.data.credentials.contains_key(&second.id));
    assert_eq!(
        claim(&mut repo, &new_grant, 1_001),
        Err(AdminAccessError::Unauthorized)
    );
    assert!(repo.data.credentials.values().all(
        |value| value.binding.user_id != target || value.state != AdminCredentialState::Active
    ));
}

#[test]
fn sole_owner_reset_and_non_owner_reset_are_rejected_without_changes() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let before = repo.data.clone();
    assert_eq!(
        reset(&mut repo, &actor, owner.id.clone()).unwrap_err(),
        AdminAccessError::LastOwner
    );
    assert_eq!(repo.data, before);
    let user = add_active(&mut repo, AdminRole::Admin);
    let admin = authenticated(&mut repo, &user, AdminCredentialKind::PersonalToken);
    let before = repo.data.clone();
    assert_eq!(
        reset(&mut repo, &admin, owner.id).unwrap_err(),
        AdminAccessError::Forbidden
    );
    assert_eq!(repo.data, before);
}

#[test]
fn setup_exact_expiry_and_single_use_do_not_issue_an_automatic_session() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let created = create(&mut repo, &actor, create_input()).unwrap();
    let grant = repo.data.credentials[&created.setup.id].clone();
    let before = repo.data.clone();
    assert_eq!(
        claim(&mut repo, &grant, 1_900),
        Err(AdminAccessError::Unauthorized)
    );
    assert_eq!(repo.data, before);
    claim(&mut repo, &grant, 1_899).unwrap();
    let mut expected_lookups = before.credentials.clone();
    expected_lookups.remove(&grant.id);
    assert_eq!(repo.data.credentials, expected_lookups);
    assert_eq!(
        repo.data.audit.last().unwrap().actor.as_str(),
        created.account.id.as_str()
    );
    let after = repo.data.clone();
    assert_eq!(
        claim(&mut repo, &grant, 1_899),
        Err(AdminAccessError::Unauthorized)
    );
    assert_eq!(repo.data, after);
}

#[test]
fn setup_audit_failure_rolls_back_password_grant_consumption_and_revocation() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let created = create(&mut repo, &actor, create_input()).unwrap();
    let grant = repo.data.credentials[&created.setup.id].clone();
    repo.fail_audit = true;
    let before = repo.data.clone();
    assert_eq!(
        claim(&mut repo, &grant, 1_001),
        Err(AdminAccessError::Unavailable)
    );
    assert_eq!(repo.data, before);
}

#[test]
fn concurrent_setup_consumption_or_reset_cannot_use_a_stale_kdf_result() {
    for consumed in [true, false] {
        let mut repo = MemoryRepository::new();
        let owner = bootstrap(&mut repo).unwrap();
        let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
        let created = create(&mut repo, &actor, create_input()).unwrap();
        let grant = repo.data.credentials[&created.setup.id].clone();
        let user_id = created.account.id;
        let grant_id = grant.id.clone();
        repo.race = Some(Box::new(move |data| {
            if consumed {
                let code = data.credentials.get_mut(&grant_id).unwrap();
                code.state = AdminCredentialState::Consumed;
                code.ended_at = Some(1_001);
            } else {
                let mut account =
                    AdminAccount::from_snapshot(data.accounts[&user_id].clone()).unwrap();
                account.begin_password_reset(1).unwrap();
                data.accounts.insert(user_id, account.snapshot());
            }
        }));
        let audits = repo.data.audit.len();
        assert_eq!(
            claim(&mut repo, &grant, 1_001),
            Err(AdminAccessError::Unauthorized)
        );
        assert_eq!(repo.data.audit.len(), audits);
        assert!(
            repo.data.accounts[&grant.binding.user_id]
                .password_verifier
                .is_none()
        );
    }
}

#[test]
fn every_active_role_can_change_own_password_and_revokes_all_own_credentials() {
    for role in [
        AdminRole::Owner,
        AdminRole::Admin,
        AdminRole::Operator,
        AdminRole::Viewer,
    ] {
        let mut repo = MemoryRepository::new();
        bootstrap(&mut repo).unwrap();
        let user = add_active(&mut repo, role);
        let actor = authenticated(&mut repo, &user, AdminCredentialKind::WebSession);
        authenticated(&mut repo, &user, AdminCredentialKind::PersonalToken);
        let (passwords, _) = dependencies(&repo);
        ChangeOwnAdminPassword::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            &passwords,
            ChangeOwnAdminPasswordInput {
                current_password: "fixture current password",
                new_password: "new own fixture password",
            },
        )
        .unwrap();
        assert_eq!(repo.data.accounts[&user].status, AdminAccountStatus::Active);
        assert_eq!(repo.data.accounts[&user].role, role);
        assert_eq!(repo.data.accounts[&user].credential_revision.value(), 2);
        assert!(
            repo.data
                .credentials
                .values()
                .filter(|value| value.binding.user_id == user)
                .all(|value| value.state == AdminCredentialState::Revoked)
        );
        assert_eq!(
            repo.data.audit.last().unwrap().actor.as_str(),
            user.as_str()
        );
    }
}

#[test]
fn own_password_wrong_proof_audit_failure_and_stale_revision_have_no_partial_effect() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let (passwords, _) = dependencies(&repo);
    let before = repo.data.clone();
    assert_eq!(
        ChangeOwnAdminPassword::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            &passwords,
            ChangeOwnAdminPasswordInput {
                current_password: "wrong fixture password",
                new_password: "new own fixture password"
            }
        ),
        Err(AdminAccessError::Unauthorized)
    );
    assert_eq!(passwords.calls.get(), 0);
    assert_eq!(repo.data, before);
    repo.fail_audit = true;
    assert_eq!(
        ChangeOwnAdminPassword::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            &passwords,
            ChangeOwnAdminPasswordInput {
                current_password: "fixture current password",
                new_password: "new own fixture password"
            }
        ),
        Err(AdminAccessError::Unavailable)
    );
    assert_eq!(repo.data, before);
    repo.fail_audit = false;
    let id = owner.id;
    repo.race = Some(Box::new(move |data| {
        let mut account = AdminAccount::from_snapshot(data.accounts[&id].clone()).unwrap();
        account
            .recover_owner(
                AdminPasswordVerifier::from_parts(
                    AdminPasswordVerifier::PROFILE_ID,
                    &[6; 16],
                    &[7; 32],
                )
                .unwrap(),
            )
            .unwrap();
        data.accounts.insert(id, account.snapshot());
    }));
    assert_eq!(
        ChangeOwnAdminPassword::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            &passwords,
            ChangeOwnAdminPasswordInput {
                current_password: "fixture current password",
                new_password: "new own fixture password"
            }
        ),
        Err(AdminAccessError::Unauthorized)
    );
    assert_eq!(repo.data.audit.len(), before.audit.len());
    assert!(repo.data.revoked_users.is_empty());
}

#[test]
fn owner_count_is_rechecked_after_another_owner_demotes() {
    let mut repo = MemoryRepository::new();
    let first = bootstrap(&mut repo).unwrap();
    let second = add_active(&mut repo, AdminRole::Owner);
    let actor = authenticated(&mut repo, &second, AdminCredentialKind::WebSession);
    repo.race = Some(Box::new(move |data| {
        let mut account = AdminAccount::from_snapshot(data.accounts[&first.id].clone()).unwrap();
        account.change_role(AdminRole::Admin, 1).unwrap();
        data.accounts.insert(first.id, account.snapshot());
    }));
    let mut input = change_input(second.clone());
    input.role = Some(AdminRole::Admin);
    assert_eq!(
        change(&mut repo, &actor, input).unwrap_err(),
        AdminAccessError::LastOwner
    );
    assert_eq!(repo.data.accounts[&second].role, AdminRole::Owner);
}

#[test]
fn late_operation_expiry_rolls_back_a_prepared_effect_and_audit() {
    struct Expiring(Cell<usize>);
    impl AdminOperation for Expiring {
        fn checked_now(&self) -> Result<i64, AdminAccessError> {
            self.0.set(self.0.get() + 1);
            if self.0.get() >= 3 {
                Err(AdminAccessError::OperationExpired)
            } else {
                Ok(1_000)
            }
        }
    }
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let (passwords, generator) = dependencies(&repo);
    let before = repo.data.clone();
    assert_eq!(
        CreateAdminAccount::execute(
            &mut repo,
            &actor,
            &Expiring(Cell::new(0)),
            &passwords,
            &generator,
            create_input()
        )
        .unwrap_err(),
        AdminAccessError::OperationExpired
    );
    assert_eq!(repo.data, before);
}

#[test]
fn setup_expiring_during_kdf_and_non_grant_purpose_cannot_change_password() {
    struct Advancing(Cell<usize>);
    impl AdminOperation for Advancing {
        fn checked_now(&self) -> Result<i64, AdminAccessError> {
            let call = self.0.get();
            self.0.set(call + 1);
            Ok(if call == 0 { 1_000 } else { 1_900 })
        }
    }
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let created = create(&mut repo, &actor, create_input()).unwrap();
    let grant = repo.data.credentials[&created.setup.id].clone();
    let (passwords, _) = dependencies(&repo);
    let before = repo.data.clone();
    assert_eq!(
        CompleteAdminSetup::execute(
            &mut repo,
            &Advancing(Cell::new(0)),
            &passwords,
            CompleteAdminSetupInput {
                kind: grant.kind,
                digest: grant.digest.clone(),
                new_password: "new fixture password"
            }
        ),
        Err(AdminAccessError::Unauthorized)
    );
    assert_eq!(passwords.calls.get(), 1);
    assert_eq!(repo.data, before);
    let session = repo.data.credentials[actor.credential_id()].clone();
    assert_eq!(
        claim(&mut repo, &session, 1_001),
        Err(AdminAccessError::Unauthorized)
    );
    assert_eq!(repo.data, before);
}

#[test]
fn reset_failure_rolls_back_and_disabled_user_can_complete_a_new_reset() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let target = add_active(&mut repo, AdminRole::Viewer);
    let old = authenticated(&mut repo, &target, AdminCredentialKind::PersonalToken);
    let before = repo.data.clone();
    repo.fail_audit = true;
    assert_eq!(
        reset(&mut repo, &actor, target.clone()).unwrap_err(),
        AdminAccessError::Unavailable
    );
    assert_eq!(repo.data, before);
    repo.fail_audit = false;
    let mut disable = change_input(target.clone());
    disable.disable = true;
    change(&mut repo, &actor, disable).unwrap();
    let reset = reset(&mut repo, &actor, target.clone()).unwrap();
    let grant = repo.data.credentials[&reset.id].clone();
    claim(&mut repo, &grant, 1_001).unwrap();
    assert_eq!(
        repo.data.accounts[&target].status,
        AdminAccountStatus::Active
    );
    assert_eq!(
        create(&mut repo, &old, create_input()).unwrap_err(),
        AdminAccessError::Unauthorized
    );
}

#[test]
fn all_password_action_inputs_redact_their_secrets() {
    let user = AdminUserId::parse("usr_00000000000000000000000000000001").unwrap();
    let create = create_input();
    let change = change_input(user.clone());
    let reset = ResetAdminPasswordInput {
        user_id: user,
        current_password: "fixture sentinel",
    };
    let setup = CompleteAdminSetupInput {
        kind: AdminCredentialKind::SetupGrant,
        digest: AdminCredentialDigest::from_bytes([0xab; 32]),
        new_password: "fixture sentinel",
    };
    let own = ChangeOwnAdminPasswordInput {
        current_password: "fixture sentinel",
        new_password: "new sentinel",
    };
    for formatted in [
        format!("{create:?}"),
        format!("{change:?}"),
        format!("{reset:?}"),
        format!("{setup:?}"),
        format!("{own:?}"),
    ] {
        assert!(!formatted.contains("sentinel"));
        assert!(!formatted.contains("fixture current password"));
        assert!(formatted.contains("[REDACTED]"));
    }
    for invalid in [
        String::new(),
        "short".to_owned(),
        "unsafe secret with spaces".repeat(3),
        "x".repeat(257),
    ] {
        assert!(AdminSecret::from_adapter(invalid).is_err());
    }
}
