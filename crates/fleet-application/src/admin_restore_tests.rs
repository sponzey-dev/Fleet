use super::*;

struct Epochs {
    next: Cell<u8>,
    locked: Rc<Cell<bool>>,
    fail: bool,
}

impl HumanAuthEpochGenerator for Epochs {
    fn fresh_epoch(&self) -> Result<HumanAuthEpoch, AdminAccessError> {
        assert!(
            !self.locked.get(),
            "entropy must be obtained before the transaction"
        );
        if self.fail {
            return Err(AdminAccessError::Unavailable);
        }
        let value = self.next.get();
        self.next.set(value + 1);
        Ok(HumanAuthEpoch::from_bytes([value; 16]))
    }
}

fn epochs(repo: &MemoryRepository) -> Epochs {
    Epochs {
        next: Cell::new(8),
        locked: repo.locked.clone(),
        fail: false,
    }
}

fn restore(
    repo: &mut MemoryRepository,
    source: &dyn HumanAuthEpochGenerator,
) -> Result<AdminAuthMode, AdminAccessError> {
    InvalidateAdminCredentialsAfterRestore::execute(
        repo,
        &Local(true),
        &Operation { fail: false },
        source,
    )
}

#[test]
fn restored_epoch_invalidates_all_four_purposes_and_preserves_accounts_verifiers_and_history() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let owner_context = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let operator = add_active(&mut repo, AdminRole::Operator);
    authenticated(&mut repo, &operator, AdminCredentialKind::PersonalToken);
    let created = create(&mut repo, &owner_context, create_input()).unwrap();
    let mut another = create_input();
    another.username = AdminUsername::parse("another.pending").unwrap();
    create(&mut repo, &owner_context, another).unwrap();
    let (passwords, ids) = dependencies(&repo);
    ResetAdminPassword::execute(
        &mut repo,
        &owner_context,
        &Operation { fail: false },
        &passwords,
        &ids,
        ResetAdminPasswordInput {
            user_id: created.account.id,
            current_password: "fixture current password",
        },
    )
    .unwrap();
    let valid: Vec<_> = repo
        .data
        .credentials
        .values()
        .filter(|credential| credential.state == AdminCredentialState::Active)
        .cloned()
        .collect();
    assert_eq!(valid.len(), 4);
    for credential in &valid {
        let account = repo
            .account_by_id(&credential.binding.user_id)
            .unwrap()
            .unwrap();
        AdminCredential::from_snapshot(credential.clone())
            .unwrap()
            .validate(
                credential.kind,
                repo.data.auth.mode,
                &account,
                repo.data.auth.epoch,
                1_000,
            )
            .unwrap();
    }
    let before = repo.data.clone();
    let source = epochs(&repo);
    assert_eq!(
        restore(&mut repo, &source).unwrap(),
        AdminAuthMode::Personal
    );
    assert_ne!(repo.data.auth.epoch, before.auth.epoch);
    assert_eq!(repo.data.accounts, before.accounts);
    assert_eq!(repo.data.credentials, before.credentials);
    assert_eq!(repo.data.revoked_users, before.revoked_users);
    assert_eq!(
        &repo.data.audit[..before.audit.len()],
        before.audit.as_slice()
    );
    let audit = repo.data.audit.last().unwrap();
    assert_eq!(audit.action, "admin_credentials_invalidated_after_restore");
    assert_eq!(audit.actor.as_str(), "local:fixture");
    assert_eq!(audit.target.as_str(), "human-auth");
    assert_eq!(audit.category, AuditCategory::Security);
    assert_eq!(audit.value, AuditValue::Redacted);
    for credential in valid {
        let account = repo
            .account_by_id(&credential.binding.user_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            AdminCredential::from_snapshot(credential.clone())
                .unwrap()
                .validate(
                    credential.kind,
                    repo.data.auth.mode,
                    &account,
                    repo.data.auth.epoch,
                    1_000
                ),
            Err(AdminCredentialError::StaleBinding)
        );
    }
    assert_eq!(
        create(&mut repo, &owner_context, create_input()).unwrap_err(),
        AdminAccessError::Unauthorized
    );
    let new_context = authenticated(&mut repo, &owner.id, AdminCredentialKind::PersonalToken);
    let first_epoch = repo.data.auth.epoch;
    restore(&mut repo, &source).unwrap();
    assert_ne!(repo.data.auth.epoch, first_epoch);
    let mut update = change_input(owner.id);
    update.display_name = Some(AdminDisplayName::parse("Still the same owner").unwrap());
    assert_eq!(
        change(&mut repo, &new_context, update).unwrap_err(),
        AdminAccessError::Unauthorized
    );
}

#[test]
fn restore_without_a_loginable_owner_requires_local_setup_and_never_revives_legacy() {
    let mut repo = MemoryRepository::new();
    let source = epochs(&repo);
    let before = repo.data.clone();
    assert_eq!(
        restore(&mut repo, &source).unwrap(),
        AdminAuthMode::LocalSetupRequired
    );
    assert_ne!(repo.data.auth.epoch, before.auth.epoch);
    assert_eq!(repo.data.accounts, before.accounts);
    assert_eq!(
        restore(&mut repo, &source).unwrap(),
        AdminAuthMode::LocalSetupRequired
    );
    bootstrap(&mut repo).unwrap();
    assert_eq!(repo.data.auth.mode, AdminAuthMode::Personal);
}

#[test]
fn restore_authority_entropy_audit_and_expiry_failures_leave_canonical_state_unchanged() {
    for failure in ["authority", "entropy", "audit", "expiry"] {
        let mut repo = MemoryRepository::new();
        bootstrap(&mut repo).unwrap();
        let before = repo.data.clone();
        let mut source = epochs(&repo);
        source.fail = failure == "entropy";
        repo.fail_audit = failure == "audit";
        let result = InvalidateAdminCredentialsAfterRestore::execute(
            &mut repo,
            &Local(failure != "authority"),
            &Operation {
                fail: failure == "expiry",
            },
            &source,
        );
        assert_eq!(
            result.unwrap_err(),
            match failure {
                "authority" => AdminAccessError::Forbidden,
                "expiry" => AdminAccessError::OperationExpired,
                _ => AdminAccessError::Unavailable,
            }
        );
        assert_eq!(repo.data, before);
    }
}

#[test]
fn restore_rejects_reused_entropy_lost_authority_and_concurrent_epoch_change() {
    struct Reused(HumanAuthEpoch);
    impl HumanAuthEpochGenerator for Reused {
        fn fresh_epoch(&self) -> Result<HumanAuthEpoch, AdminAccessError> {
            Ok(self.0)
        }
    }
    struct Lost(Cell<u8>);
    impl AdminLocalAuthority for Lost {
        fn require_exclusive(&self) -> Result<AuditActor, AdminAccessError> {
            let calls = self.0.get();
            self.0.set(calls + 1);
            if calls == 0 {
                Ok(AuditActor::new("local:fixture"))
            } else {
                Err(AdminAccessError::Forbidden)
            }
        }
    }
    let mut repo = MemoryRepository::new();
    bootstrap(&mut repo).unwrap();
    let before = repo.data.clone();
    assert_eq!(
        restore(&mut repo, &Reused(before.auth.epoch)).unwrap_err(),
        AdminAccessError::Unavailable
    );
    let source = epochs(&repo);
    assert_eq!(
        InvalidateAdminCredentialsAfterRestore::execute(
            &mut repo,
            &Lost(Cell::new(0)),
            &Operation { fail: false },
            &source
        )
        .unwrap_err(),
        AdminAccessError::Forbidden
    );
    assert_eq!(repo.data, before);
    let raced_epoch = HumanAuthEpoch::from_bytes([99; 16]);
    repo.race = Some(Box::new(move |data| data.auth.epoch = raced_epoch));
    assert_eq!(
        restore(&mut repo, &source).unwrap_err(),
        AdminAccessError::Conflict
    );
    let mut expected = before;
    expected.auth.epoch = raced_epoch;
    assert_eq!(repo.data, expected);
}
