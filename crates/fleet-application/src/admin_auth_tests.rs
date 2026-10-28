use super::*;

struct Clock(Rc<Cell<i64>>);

#[test]
fn personal_token_revoke_treats_a_retained_revoked_lookup_as_not_found_without_effects() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let token = authenticated(&mut repo, &owner.id, AdminCredentialKind::PersonalToken);
    let row = repo
        .data
        .credentials
        .get_mut(token.credential_id())
        .unwrap();
    row.state = AdminCredentialState::Revoked;
    row.ended_at = Some(1_000);
    let before = repo.data.clone();
    assert_eq!(
        RevokeOwnAdminPersonalToken::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            token.credential_id()
        ),
        Err(AdminAccessError::NotFound)
    );
    assert_eq!(
        repo.data, before,
        "pending bounded lookup reclamation must not change the public deletion result"
    );
}
impl AdminOperation for Clock {
    fn checked_now(&self) -> Result<i64, AdminAccessError> {
        Ok(self.0.get())
    }
}

struct MovingPassword<'a> {
    inner: Passwords,
    clock: &'a Clock,
    after: i64,
}
impl AdminPasswordPort for MovingPassword<'_> {
    fn hash_new(
        &self,
        input: &str,
        user: &AdminUsername,
    ) -> Result<AdminPasswordVerifier, AdminAccessError> {
        self.inner.hash_new(input, user)
    }
    fn verify(
        &self,
        input: &str,
        verifier: Option<&AdminPasswordVerifier>,
    ) -> Result<bool, AdminAccessError> {
        let result = self.inner.verify(input, verifier)?;
        self.clock.0.set(self.after);
        Ok(result)
    }
}

fn login_input() -> LoginAdminInput<'static> {
    LoginAdminInput {
        username: "FIRST.OWNER",
        password: "fixture current password",
    }
}

#[test]
fn login_issues_fixed_eight_hour_session_with_server_identity_and_no_poll_renewal() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let (passwords, generator) = dependencies(&repo);
    let clock = Clock(Rc::new(Cell::new(1_000)));
    let result =
        LoginAdmin::execute(&mut repo, &clock, &passwords, &generator, login_input()).unwrap();
    assert_eq!(result.account.id, owner.id);
    assert_eq!(result.account.username.as_str(), "first.owner");
    assert_eq!(result.session.kind, AdminCredentialKind::WebSession);
    assert_eq!(result.session.expires_at, 29_800);
    let stored = repo
        .credential_by_id(&result.session.id)
        .unwrap()
        .unwrap()
        .snapshot();
    assert_eq!(stored.created_at, 1_000);
    assert_eq!(stored.expires_at, 29_800);
    for now in [1_000, 20_000, 29_799] {
        clock.0.set(now);
        let context = AuthenticateAdminCredential::execute(
            &repo,
            &clock,
            AdminCredentialKind::WebSession,
            &stored.digest,
        )
        .unwrap();
        assert_eq!(context.user_id(), &owner.id);
        assert_eq!(
            repo.credential_by_id(&result.session.id)
                .unwrap()
                .unwrap()
                .snapshot()
                .expires_at,
            29_800
        );
    }
    for now in [29_800, 29_801] {
        clock.0.set(now);
        assert_eq!(
            AuthenticateAdminCredential::execute(
                &repo,
                &clock,
                AdminCredentialKind::WebSession,
                &stored.digest
            )
            .unwrap_err(),
            AdminAccessError::Unauthorized
        );
    }
    let event = repo.data.audit.last().unwrap();
    assert_eq!(event.action, "admin_session_created");
    assert_eq!(event.actor.as_str(), owner.id.as_str());
    assert_eq!(event.value, AuditValue::Redacted);
    let secret = result.session.secret.expose_for_delivery();
    assert!(!format!("{result:?} {:?} {:?}", repo.data, login_input()).contains(secret));
    assert!(!format!("{:?}", login_input()).contains("fixture current password"));
}

struct RecordedPassword {
    inner: Passwords,
    calls: Cell<usize>,
    dummy: Cell<usize>,
}
impl AdminPasswordPort for RecordedPassword {
    fn hash_new(
        &self,
        input: &str,
        user: &AdminUsername,
    ) -> Result<AdminPasswordVerifier, AdminAccessError> {
        self.inner.hash_new(input, user)
    }
    fn verify(
        &self,
        input: &str,
        verifier: Option<&AdminPasswordVerifier>,
    ) -> Result<bool, AdminAccessError> {
        self.calls.set(self.calls.get() + 1);
        self.dummy
            .set(self.dummy.get() + usize::from(verifier.is_none()));
        self.inner.verify(input, verifier)
    }
}

#[test]
fn login_wrong_unknown_invalid_inactive_or_wrong_mode_is_generic_and_runs_real_or_dummy_verify() {
    for case in [
        "wrong", "unknown", "invalid", "disabled", "pending", "legacy", "local",
    ] {
        let mut repo = MemoryRepository::new();
        let owner = bootstrap(&mut repo).unwrap();
        if matches!(case, "disabled" | "pending") {
            let mut backup = AdminAccount::pending(
                AdminUserId::parse(format!("usr_{:032x}", 2)).unwrap(),
                AdminUsername::parse("backup.owner").unwrap(),
                AdminDisplayName::parse("Backup owner").unwrap(),
                AdminRole::Owner,
            );
            backup
                .install_password(
                    repo.data.accounts[&owner.id]
                        .password_verifier
                        .clone()
                        .unwrap(),
                )
                .unwrap();
            repo.data
                .accounts
                .insert(backup.snapshot().id, backup.snapshot());
        }
        let mut input = login_input();
        match case {
            "wrong" => input.password = "wrong synthetic password",
            "unknown" => input.username = "missing.user",
            "invalid" => input.username = " first.owner ",
            "disabled" => {
                let mut account = repo.account_by_id(&owner.id).unwrap().unwrap();
                account.disable(1).unwrap();
                repo.data
                    .accounts
                    .insert(owner.id.clone(), account.snapshot());
            }
            "pending" => {
                let mut account = repo.account_by_id(&owner.id).unwrap().unwrap();
                account.begin_password_reset(1).unwrap();
                repo.data
                    .accounts
                    .insert(owner.id.clone(), account.snapshot());
            }
            "legacy" => {
                repo.data.accounts.clear();
                repo.data.auth.mode = AdminAuthMode::LegacyBootstrap;
            }
            "local" => {
                repo.data.accounts.clear();
                repo.data.auth.mode = AdminAuthMode::LocalSetupRequired;
            }
            _ => unreachable!(),
        }
        let (inner, generator) = dependencies(&repo);
        let passwords = RecordedPassword {
            inner,
            calls: Cell::new(0),
            dummy: Cell::new(0),
        };
        let before = repo.data.clone();
        assert_eq!(
            LoginAdmin::execute(
                &mut repo,
                &Operation { fail: false },
                &passwords,
                &generator,
                input
            )
            .unwrap_err(),
            AdminAccessError::Unauthorized
        );
        assert_eq!(passwords.calls.get(), 1);
        assert_eq!(passwords.dummy.get(), usize::from(case != "wrong"));
        assert_eq!(repo.data, before);
        assert_eq!(generator.credential_next.get(), 0);
    }
}

#[test]
fn login_rechecks_password_role_reset_disable_epoch_and_mode_after_password_work() {
    for case in [
        "password", "role", "reset", "disable", "epoch", "mode", "metadata",
    ] {
        let mut repo = MemoryRepository::new();
        bootstrap(&mut repo).unwrap();
        let id = AdminUserId::parse(format!("usr_{:032x}", 2)).unwrap();
        let mut account = AdminAccount::pending(
            id.clone(),
            AdminUsername::parse("other.user").unwrap(),
            AdminDisplayName::parse("Other").unwrap(),
            AdminRole::Operator,
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
        repo.data.accounts.insert(id.clone(), account.snapshot());
        let (passwords, generator) = dependencies(&repo);
        let user = id.clone();
        repo.race = Some(Box::new(move |data| {
            let mut account = AdminAccount::from_snapshot(data.accounts[&user].clone()).unwrap();
            match case {
                "password" => {
                    account
                        .install_password(
                            AdminPasswordVerifier::from_parts(
                                AdminPasswordVerifier::PROFILE_ID,
                                &[7; 16],
                                &[8; 32],
                            )
                            .unwrap(),
                        )
                        .unwrap();
                }
                "role" => {
                    account.change_role(AdminRole::Viewer, 1).unwrap();
                }
                "reset" => {
                    account.begin_password_reset(1).unwrap();
                }
                "disable" => {
                    account.disable(1).unwrap();
                }
                "epoch" => data.auth.epoch = HumanAuthEpoch::from_bytes([9; 16]),
                "mode" => data.auth.mode = AdminAuthMode::LocalSetupRequired,
                "metadata" => {
                    account
                        .rename(AdminDisplayName::parse("Renamed").unwrap())
                        .unwrap();
                }
                _ => unreachable!(),
            }
            data.accounts.insert(user, account.snapshot());
        }));
        let result = LoginAdmin::execute(
            &mut repo,
            &Operation { fail: false },
            &passwords,
            &generator,
            LoginAdminInput {
                username: "other.user",
                password: "fixture current password",
            },
        );
        if case == "metadata" {
            assert_eq!(result.unwrap().account.display_name.as_str(), "Renamed");
        } else {
            assert_eq!(result.unwrap_err(), AdminAccessError::Unauthorized);
            assert!(repo.data.credentials.is_empty());
            assert_eq!(repo.data.audit.len(), 1);
        }
    }
}

#[test]
fn login_audit_failure_and_expired_operation_never_issue_a_session() {
    for expired in [false, true] {
        let mut repo = MemoryRepository::new();
        bootstrap(&mut repo).unwrap();
        let (passwords, generator) = dependencies(&repo);
        repo.fail_audit = !expired;
        let before = repo.data.clone();
        assert_eq!(
            LoginAdmin::execute(
                &mut repo,
                &Operation { fail: expired },
                &passwords,
                &generator,
                login_input()
            )
            .unwrap_err(),
            if expired {
                AdminAccessError::OperationExpired
            } else {
                AdminAccessError::Unavailable
            }
        );
        assert_eq!(repo.data, before);
    }
}

#[test]
fn login_session_admission_enforces_current_user_eight_and_commits_no_ninth_credential_or_audit() {
    let mut repo = MemoryRepository::new();
    bootstrap(&mut repo).unwrap();
    let (passwords, generator) = dependencies(&repo);
    for _ in 0..8 {
        LoginAdmin::execute(
            &mut repo,
            &Operation { fail: false },
            &passwords,
            &generator,
            login_input(),
        )
        .unwrap();
    }
    let before = repo.data.clone();
    assert_eq!(
        LoginAdmin::execute(
            &mut repo,
            &Operation { fail: false },
            &passwords,
            &generator,
            login_input()
        )
        .unwrap_err(),
        AdminAccessError::Limit
    );
    assert_eq!(repo.data, before);
}

#[test]
fn login_counts_remaining_physical_rows_and_cleanup_makes_bounded_progress_even_when_admission_is_denied()
 {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let account = repo.account_by_id(&owner.id).unwrap().unwrap();
    // An imported over-budget snapshot must recover through bounded cleanup; counting only
    // currently valid rows would wrongly admit the first login and hide the physical backlog.
    for value in 10_000_u128..14_229 {
        let mut digest = [0; 32];
        digest[..16].copy_from_slice(&value.to_be_bytes());
        let credential = AdminCredential::issue(
            AdminCredentialId::parse(format!("crd_{value:032x}")).unwrap(),
            AdminCredentialKind::WebSession,
            AdminCredentialDigest::from_bytes(digest),
            AdminCredentialBinding::for_account(&account, HumanAuthEpoch::from_bytes([9; 16])),
            900,
        )
        .unwrap()
        .snapshot();
        repo.data
            .credentials
            .insert(credential.id.clone(), credential);
    }
    let (passwords, generator) = dependencies(&repo);
    let old_accounts = repo.data.accounts.clone();
    let old_audit = repo.data.audit.clone();
    assert_eq!(
        LoginAdmin::execute(
            &mut repo,
            &Operation { fail: false },
            &passwords,
            &generator,
            login_input()
        )
        .unwrap_err(),
        AdminAccessError::Limit
    );
    assert_eq!(repo.data.credentials.len(), 4_101); // Exactly 128, never an unbounded sweep.
    assert_eq!(repo.data.accounts, old_accounts);
    assert_eq!(repo.data.audit, old_audit);
    LoginAdmin::execute(
        &mut repo,
        &Operation { fail: false },
        &passwords,
        &generator,
        login_input(),
    )
    .unwrap();
    assert_eq!(repo.data.credentials.len(), 3_974); // Another 128 reclaimed, then one session.
}

#[test]
fn login_rejects_clock_regression_during_password_work_and_uses_commit_time_for_expiry() {
    for after in [999, 1_001] {
        let mut repo = MemoryRepository::new();
        bootstrap(&mut repo).unwrap();
        let (inner, generator) = dependencies(&repo);
        let clock = Clock(Rc::new(Cell::new(1_000)));
        let passwords = MovingPassword {
            inner,
            clock: &clock,
            after,
        };
        let before = repo.data.clone();
        let result = LoginAdmin::execute(&mut repo, &clock, &passwords, &generator, login_input());
        if after < 1_000 {
            assert_eq!(result.unwrap_err(), AdminAccessError::OperationExpired);
            assert_eq!(repo.data, before);
        } else {
            assert_eq!(result.unwrap().session.expires_at, 29_801);
        }
    }
    let mut repo = MemoryRepository::new();
    bootstrap(&mut repo).unwrap();
    let (inner, generator) = dependencies(&repo);
    let clock = Clock(Rc::new(Cell::new(1_000)));
    let concurrent_clock = clock.0.clone();
    repo.race = Some(Box::new(move |_| concurrent_clock.set(1_001)));
    let passwords = MovingPassword {
        inner,
        clock: &clock,
        after: 1_002,
    };
    let before = repo.data.clone();
    assert_eq!(
        LoginAdmin::execute(&mut repo, &clock, &passwords, &generator, login_input()).unwrap_err(),
        AdminAccessError::OperationExpired
    );
    assert_eq!(repo.data, before);
}

#[test]
fn login_cancellation_after_password_verification_prevents_transaction_effects() {
    struct Cancelled(Rc<Cell<bool>>);
    impl AdminOperation for Cancelled {
        fn checked_now(&self) -> Result<i64, AdminAccessError> {
            if self.0.get() {
                Err(AdminAccessError::OperationExpired)
            } else {
                Ok(1_000)
            }
        }
    }
    let mut repo = MemoryRepository::new();
    bootstrap(&mut repo).unwrap();
    let (passwords, generator) = dependencies(&repo);
    let operation = Cancelled(Rc::new(Cell::new(false)));
    let cancellation = operation.0.clone();
    repo.race = Some(Box::new(move |_| cancellation.set(true)));
    let before = repo.data.clone();
    assert_eq!(
        LoginAdmin::execute(&mut repo, &operation, &passwords, &generator, login_input())
            .unwrap_err(),
        AdminAccessError::OperationExpired
    );
    assert_eq!(repo.data, before);
}

fn token_input() -> CreateAdminPersonalTokenInput<'static> {
    CreateAdminPersonalTokenInput {
        current_password: "fixture current password",
        label: Some(AdminTokenLabel::parse("My CLI").unwrap()),
    }
}

#[test]
fn personal_token_creation_requires_current_password_and_issues_independent_fixed_thirty_day_proof()
{
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let (passwords, generator) = dependencies(&repo);
    let clock = Clock(Rc::new(Cell::new(1_000)));
    let token = CreateAdminPersonalToken::execute(
        &mut repo,
        &actor,
        &clock,
        &passwords,
        &generator,
        token_input(),
    )
    .unwrap();
    assert_eq!(token.kind, AdminCredentialKind::PersonalToken);
    assert_eq!(token.expires_at, 2_593_000);
    let stored = repo
        .credential_by_id(&token.id)
        .unwrap()
        .unwrap()
        .snapshot();
    assert_eq!(stored.label.as_ref().unwrap().as_str(), "My CLI");
    for now in [1_000, 2_592_999] {
        clock.0.set(now);
        let context = AuthenticateAdminCredential::execute(
            &repo,
            &clock,
            AdminCredentialKind::PersonalToken,
            &stored.digest,
        )
        .unwrap();
        assert_eq!(context.user_id(), &owner.id);
    }
    for now in [2_593_000, 2_593_001] {
        clock.0.set(now);
        assert_eq!(
            AuthenticateAdminCredential::execute(
                &repo,
                &clock,
                AdminCredentialKind::PersonalToken,
                &stored.digest
            )
            .unwrap_err(),
            AdminAccessError::Unauthorized
        );
    }
    assert!(
        !format!("{token:?} {:?} {:?}", repo.data, token_input())
            .contains(token.secret.expose_for_delivery())
    );
    assert!(!format!("{:?}", token_input()).contains("fixture current password"));
    let event = repo.data.audit.last().unwrap();
    assert_eq!(event.action, "admin_personal_token_created");
    assert_eq!(event.actor.as_str(), owner.id.as_str());
    assert_eq!(event.target.as_str(), token.id.as_str());
}

#[test]
fn every_active_role_can_mint_only_with_its_own_current_password_and_current_credential() {
    for role in [
        AdminRole::Owner,
        AdminRole::Admin,
        AdminRole::Operator,
        AdminRole::Viewer,
    ] {
        let mut repo = MemoryRepository::new();
        let owner = bootstrap(&mut repo).unwrap();
        let mut account = AdminAccount::pending(
            AdminUserId::parse(format!("usr_{:032x}", 2)).unwrap(),
            AdminUsername::parse("other.user").unwrap(),
            AdminDisplayName::parse("Other user").unwrap(),
            role,
        );
        account
            .install_password(
                repo.data.accounts[&owner.id]
                    .password_verifier
                    .clone()
                    .unwrap(),
            )
            .unwrap();
        let id = account.snapshot().id;
        repo.data.accounts.insert(id.clone(), account.snapshot());
        let actor = authenticated(&mut repo, &id, AdminCredentialKind::WebSession);
        let (passwords, generator) = dependencies(&repo);
        let before = repo.data.clone();
        assert_eq!(
            CreateAdminPersonalToken::execute(
                &mut repo,
                &actor,
                &Operation { fail: false },
                &passwords,
                &generator,
                CreateAdminPersonalTokenInput {
                    current_password: "wrong synthetic password",
                    label: None
                }
            )
            .unwrap_err(),
            AdminAccessError::Unauthorized
        );
        assert_eq!(repo.data, before);
        let token = CreateAdminPersonalToken::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            &passwords,
            &generator,
            token_input(),
        )
        .unwrap();
        assert_eq!(
            repo.credential_by_id(&token.id)
                .unwrap()
                .unwrap()
                .snapshot()
                .binding
                .user_id,
            id
        );
    }
}

#[test]
fn personal_token_current_user_limit_is_sixteen_and_excess_has_no_issuance_or_audit() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let (passwords, generator) = dependencies(&repo);
    for _ in 0..16 {
        CreateAdminPersonalToken::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            &passwords,
            &generator,
            token_input(),
        )
        .unwrap();
    }
    let before = repo.data.clone();
    assert_eq!(
        CreateAdminPersonalToken::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            &passwords,
            &generator,
            token_input()
        )
        .unwrap_err(),
        AdminAccessError::Limit
    );
    assert_eq!(repo.data, before);
}

#[test]
fn personal_token_global_cap_counts_stale_physical_rows_after_bounded_cleanup() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let account = repo.account_by_id(&owner.id).unwrap().unwrap();
    for value in 10_000_u128..18_325 {
        let mut digest = [0; 32];
        digest[..16].copy_from_slice(&value.to_be_bytes());
        let credential = AdminCredential::issue(
            AdminCredentialId::parse(format!("crd_{value:032x}")).unwrap(),
            AdminCredentialKind::PersonalToken,
            AdminCredentialDigest::from_bytes(digest),
            AdminCredentialBinding::for_account(&account, HumanAuthEpoch::from_bytes([9; 16])),
            900,
        )
        .unwrap()
        .snapshot();
        repo.data
            .credentials
            .insert(credential.id.clone(), credential);
    }
    let (passwords, generator) = dependencies(&repo);
    let old_audit = repo.data.audit.clone();
    assert_eq!(
        CreateAdminPersonalToken::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            &passwords,
            &generator,
            token_input()
        )
        .unwrap_err(),
        AdminAccessError::Limit
    );
    assert_eq!(
        repo.data
            .credentials
            .values()
            .filter(|c| c.kind == AdminCredentialKind::PersonalToken)
            .count(),
        8_197
    );
    assert_eq!(repo.data.audit, old_audit);
    CreateAdminPersonalToken::execute(
        &mut repo,
        &actor,
        &Operation { fail: false },
        &passwords,
        &generator,
        token_input(),
    )
    .unwrap();
    assert_eq!(
        repo.data
            .credentials
            .values()
            .filter(|c| c.kind == AdminCredentialKind::PersonalToken)
            .count(),
        8_070
    );
}

#[test]
fn personal_token_creation_rechecks_account_credential_and_restore_changes_before_commit() {
    for case in [
        "password", "role", "reset", "disable", "epoch", "revoke", "metadata", "audit",
    ] {
        let mut repo = MemoryRepository::new();
        let owner = bootstrap(&mut repo).unwrap();
        let mut account = AdminAccount::pending(
            AdminUserId::parse(format!("usr_{:032x}", 2)).unwrap(),
            AdminUsername::parse("other.user").unwrap(),
            AdminDisplayName::parse("Other").unwrap(),
            AdminRole::Operator,
        );
        account
            .install_password(
                repo.data.accounts[&owner.id]
                    .password_verifier
                    .clone()
                    .unwrap(),
            )
            .unwrap();
        let id = account.snapshot().id;
        repo.data.accounts.insert(id.clone(), account.snapshot());
        let actor = authenticated(&mut repo, &id, AdminCredentialKind::WebSession);
        let (passwords, generator) = dependencies(&repo);
        if case == "audit" {
            repo.fail_audit = true;
        } else {
            let credential = actor.credential_id().clone();
            repo.race = Some(Box::new(move |data| {
                let mut account = AdminAccount::from_snapshot(data.accounts[&id].clone()).unwrap();
                match case {
                    "password" => {
                        account
                            .install_password(
                                AdminPasswordVerifier::from_parts(
                                    AdminPasswordVerifier::PROFILE_ID,
                                    &[7; 16],
                                    &[8; 32],
                                )
                                .unwrap(),
                            )
                            .unwrap();
                    }
                    "role" => {
                        account.change_role(AdminRole::Viewer, 1).unwrap();
                    }
                    "reset" => {
                        account.begin_password_reset(1).unwrap();
                    }
                    "disable" => {
                        account.disable(1).unwrap();
                    }
                    "epoch" => data.auth.epoch = HumanAuthEpoch::from_bytes([9; 16]),
                    "revoke" => {
                        let row = data.credentials.get_mut(&credential).unwrap();
                        row.state = AdminCredentialState::Revoked;
                        row.ended_at = Some(1_000);
                    }
                    "metadata" => {
                        account
                            .rename(AdminDisplayName::parse("Renamed").unwrap())
                            .unwrap();
                    }
                    _ => unreachable!(),
                }
                data.accounts.insert(id, account.snapshot());
            }));
        }
        let result = CreateAdminPersonalToken::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            &passwords,
            &generator,
            token_input(),
        );
        if case == "metadata" {
            assert!(result.is_ok());
        } else {
            assert_eq!(
                result.unwrap_err(),
                if case == "audit" {
                    AdminAccessError::Unavailable
                } else {
                    AdminAccessError::Unauthorized
                }
            );
            assert_eq!(
                repo.data
                    .credentials
                    .values()
                    .filter(|c| c.kind == AdminCredentialKind::PersonalToken)
                    .count(),
                0
            );
            assert_eq!(repo.data.audit.len(), 1);
        }
    }
}

#[test]
fn personal_token_creation_cannot_extend_an_actor_session_that_expires_during_password_work() {
    for after in [29_799, 29_800] {
        let mut repo = MemoryRepository::new();
        let owner = bootstrap(&mut repo).unwrap();
        let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
        let (inner, generator) = dependencies(&repo);
        let clock = Clock(Rc::new(Cell::new(29_799)));
        let passwords = MovingPassword {
            inner,
            clock: &clock,
            after,
        };
        let result = CreateAdminPersonalToken::execute(
            &mut repo,
            &actor,
            &clock,
            &passwords,
            &generator,
            token_input(),
        );
        if after == 29_799 {
            assert_eq!(result.unwrap().expires_at, 2_621_799);
        } else {
            assert_eq!(result.unwrap_err(), AdminAccessError::Unauthorized);
            assert_eq!(repo.data.credentials.len(), 1);
        }
    }
}

#[test]
fn own_personal_token_metadata_is_bounded_scoped_and_never_reveals_proof_material() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let (passwords, generator) = dependencies(&repo);
    let mut secrets = Vec::new();
    for _ in 0..4 {
        let token = CreateAdminPersonalToken::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            &passwords,
            &generator,
            token_input(),
        )
        .unwrap();
        secrets.push(token.secret.expose_for_delivery().to_owned());
    }
    let mut other = AdminAccount::pending(
        AdminUserId::parse(format!("usr_{:032x}", 2)).unwrap(),
        AdminUsername::parse("other.user").unwrap(),
        AdminDisplayName::parse("Other").unwrap(),
        AdminRole::Viewer,
    );
    other
        .install_password(
            repo.data.accounts[&owner.id]
                .password_verifier
                .clone()
                .unwrap(),
        )
        .unwrap();
    let other_id = other.snapshot().id;
    repo.data
        .accounts
        .insert(other_id.clone(), other.snapshot());
    let other_actor = authenticated(&mut repo, &other_id, AdminCredentialKind::PersonalToken);
    let before = repo.data.clone();
    let first = ListOwnAdminPersonalTokens::execute(
        &repo,
        &actor,
        &Operation { fail: false },
        ListOwnAdminPersonalTokensInput {
            after: None,
            limit: AdminMetadataPageSize::new(2).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(first.items.len(), 2);
    assert_eq!(
        first.next_after.as_ref(),
        Some(&first.items.last().unwrap().id)
    );
    assert!(
        first
            .items
            .iter()
            .all(|row| row.active && row.label.as_ref().unwrap().as_str() == "My CLI")
    );
    let second = ListOwnAdminPersonalTokens::execute(
        &repo,
        &actor,
        &Operation { fail: false },
        ListOwnAdminPersonalTokensInput {
            after: first.next_after.as_ref(),
            limit: AdminMetadataPageSize::new(2).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(second.items.len(), 2);
    assert!(second.next_after.is_none());
    assert!(
        !first
            .items
            .iter()
            .any(|a| second.items.iter().any(|b| a.id == b.id))
    );
    let other_page = ListOwnAdminPersonalTokens::execute(
        &repo,
        &other_actor,
        &Operation { fail: false },
        ListOwnAdminPersonalTokensInput {
            after: None,
            limit: AdminMetadataPageSize::default(),
        },
    )
    .unwrap();
    assert_eq!(other_page.items.len(), 1);
    assert_eq!(&other_page.items[0].id, other_actor.credential_id());
    let diagnostic = format!("{first:?} {second:?} {other_page:?}");
    assert!(secrets.iter().all(|secret| !diagnostic.contains(secret)));
    assert!(
        !diagnostic.contains("digest")
            && !diagnostic.contains("binding")
            && !diagnostic.contains("password")
    );
    assert_eq!(repo.data, before); // GET-equivalent query never cleans up or renews credentials.
    assert_eq!(AdminMetadataPageSize::default().get(), 25);
    assert_eq!(AdminMetadataPageSize::new(100).unwrap().get(), 100);
    for invalid in [0, 101] {
        assert_eq!(
            AdminMetadataPageSize::new(invalid),
            Err(AdminAccessError::InvalidRequest)
        );
    }
}

#[test]
fn metadata_marks_future_or_retired_proofs_inactive_and_requires_current_caller() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let (passwords, generator) = dependencies(&repo);
    let token = CreateAdminPersonalToken::execute(
        &mut repo,
        &actor,
        &Operation { fail: false },
        &passwords,
        &generator,
        token_input(),
    )
    .unwrap();
    let mut retired = repo.data.credentials[&token.id].clone();
    retired.binding.epoch = HumanAuthEpoch::from_bytes([9; 16]);
    repo.data.credentials.insert(token.id.clone(), retired);
    let account = repo.account_by_id(&owner.id).unwrap().unwrap();
    let future = AdminCredential::issue(
        AdminCredentialId::parse(format!("crd_{:032x}", 99)).unwrap(),
        AdminCredentialKind::PersonalToken,
        AdminCredentialDigest::from_bytes([99; 32]),
        AdminCredentialBinding::for_account(&account, repo.data.auth.epoch),
        1_001,
    )
    .unwrap()
    .snapshot();
    repo.data.credentials.insert(future.id.clone(), future);
    let page = ListOwnAdminPersonalTokens::execute(
        &repo,
        &actor,
        &Operation { fail: false },
        ListOwnAdminPersonalTokensInput {
            after: None,
            limit: AdminMetadataPageSize::default(),
        },
    )
    .unwrap();
    assert_eq!(page.items.len(), 2);
    assert!(page.items.iter().all(|row| !row.active));
    let before = repo.data.clone();
    repo.data.auth.epoch = HumanAuthEpoch::from_bytes([10; 16]);
    assert_eq!(
        ListOwnAdminPersonalTokens::execute(
            &repo,
            &actor,
            &Operation { fail: false },
            ListOwnAdminPersonalTokensInput {
                after: None,
                limit: AdminMetadataPageSize::default()
            }
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
    assert_eq!(repo.data.credentials, before.credentials);
}

#[test]
fn personal_token_metadata_rejects_foreign_lookahead_rows_without_exposing_a_continuation() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let (passwords, generator) = dependencies(&repo);
    let token = CreateAdminPersonalToken::execute(
        &mut repo,
        &actor,
        &Operation { fail: false },
        &passwords,
        &generator,
        token_input(),
    )
    .unwrap();
    let mut other = AdminAccount::pending(
        AdminUserId::parse(format!("usr_{:032x}", 2)).unwrap(),
        AdminUsername::parse("other.user").unwrap(),
        AdminDisplayName::parse("Other").unwrap(),
        AdminRole::Viewer,
    );
    other
        .install_password(
            repo.data.accounts[&owner.id]
                .password_verifier
                .clone()
                .unwrap(),
        )
        .unwrap();
    let other_id = other.snapshot().id;
    repo.data
        .accounts
        .insert(other_id.clone(), other.snapshot());
    let other_actor = authenticated(&mut repo, &other_id, AdminCredentialKind::PersonalToken);
    repo.query_override = Some(vec![
        repo.credential_by_id(&token.id).unwrap().unwrap(),
        repo.credential_by_id(other_actor.credential_id())
            .unwrap()
            .unwrap(),
    ]);
    assert_eq!(
        ListOwnAdminPersonalTokens::execute(
            &repo,
            &actor,
            &Operation { fail: false },
            ListOwnAdminPersonalTokensInput {
                after: None,
                limit: AdminMetadataPageSize::new(1).unwrap()
            }
        )
        .unwrap_err(),
        AdminAccessError::Unavailable
    );
}

#[test]
fn web_logout_revokes_only_this_session_preserving_other_proofs_accounts_and_epoch() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let sibling = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let pat = authenticated(&mut repo, &owner.id, AdminCredentialKind::PersonalToken);
    let digest = repo.data.credentials[actor.credential_id()].digest.clone();
    let sibling_row = repo.data.credentials[sibling.credential_id()].clone();
    let pat_row = repo.data.credentials[pat.credential_id()].clone();
    let accounts = repo.data.accounts.clone();
    let state = repo.data.auth;
    LogoutAdminSession::execute(&mut repo, &actor, &Operation { fail: false }).unwrap();
    assert!(
        repo.credential_by_id(actor.credential_id())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        AuthenticateAdminCredential::execute(
            &repo,
            &Operation { fail: false },
            AdminCredentialKind::WebSession,
            &digest
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
    AuthenticateAdminCredential::execute(
        &repo,
        &Operation { fail: false },
        AdminCredentialKind::WebSession,
        &sibling_row.digest,
    )
    .unwrap();
    AuthenticateAdminCredential::execute(
        &repo,
        &Operation { fail: false },
        AdminCredentialKind::PersonalToken,
        &pat_row.digest,
    )
    .unwrap();
    assert_eq!(repo.data.accounts, accounts);
    assert_eq!(repo.data.auth, state);
    let before = repo.data.clone();
    assert_eq!(
        LogoutAdminSession::execute(&mut repo, &actor, &Operation { fail: false }),
        Err(AdminAccessError::Unauthorized)
    );
    assert_eq!(
        LogoutAdminSession::execute(&mut repo, &pat, &Operation { fail: false }),
        Err(AdminAccessError::Forbidden)
    );
    assert_eq!(repo.data, before);
    let event = repo.data.audit.last().unwrap();
    assert_eq!(event.action, "admin_session_logged_out");
    assert_eq!(event.actor.as_str(), owner.id.as_str());
    assert_eq!(event.target.as_str(), actor.credential_id().as_str());
}

#[test]
fn personal_token_revoke_is_self_scoped_has_uniform_not_found_and_can_revoke_its_own_caller() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let first = authenticated(&mut repo, &owner.id, AdminCredentialKind::PersonalToken);
    let sibling = authenticated(&mut repo, &owner.id, AdminCredentialKind::PersonalToken);
    let first_digest = repo.data.credentials[first.credential_id()].digest.clone();
    let sibling_row = repo.data.credentials[sibling.credential_id()].clone();
    let mut other = AdminAccount::pending(
        AdminUserId::parse(format!("usr_{:032x}", 2)).unwrap(),
        AdminUsername::parse("other.user").unwrap(),
        AdminDisplayName::parse("Other").unwrap(),
        AdminRole::Viewer,
    );
    other
        .install_password(
            repo.data.accounts[&owner.id]
                .password_verifier
                .clone()
                .unwrap(),
        )
        .unwrap();
    let other_id = other.snapshot().id;
    repo.data
        .accounts
        .insert(other_id.clone(), other.snapshot());
    let foreign = authenticated(&mut repo, &other_id, AdminCredentialKind::PersonalToken);
    let before = repo.data.clone();
    for id in [
        foreign.credential_id().clone(),
        actor.credential_id().clone(),
        AdminCredentialId::parse(format!("crd_{:032x}", 99)).unwrap(),
    ] {
        assert_eq!(
            RevokeOwnAdminPersonalToken::execute(
                &mut repo,
                &actor,
                &Operation { fail: false },
                &id
            ),
            Err(AdminAccessError::NotFound)
        );
        assert_eq!(repo.data, before);
    }
    RevokeOwnAdminPersonalToken::execute(
        &mut repo,
        &actor,
        &Operation { fail: false },
        first.credential_id(),
    )
    .unwrap();
    assert!(
        repo.credential_by_id(first.credential_id())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        AuthenticateAdminCredential::execute(
            &repo,
            &Operation { fail: false },
            AdminCredentialKind::PersonalToken,
            &first_digest
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
    AuthenticateAdminCredential::execute(
        &repo,
        &Operation { fail: false },
        AdminCredentialKind::PersonalToken,
        &sibling_row.digest,
    )
    .unwrap();
    assert_eq!(
        RevokeOwnAdminPersonalToken::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            first.credential_id()
        ),
        Err(AdminAccessError::NotFound)
    );
    RevokeOwnAdminPersonalToken::execute(
        &mut repo,
        &sibling,
        &Operation { fail: false },
        sibling.credential_id(),
    )
    .unwrap();
    assert_eq!(
        AuthenticateAdminCredential::execute(
            &repo,
            &Operation { fail: false },
            AdminCredentialKind::PersonalToken,
            &sibling_row.digest
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
    assert!(
        repo.credential_by_id(actor.credential_id())
            .unwrap()
            .is_some()
    );
    assert!(
        repo.credential_by_id(foreign.credential_id())
            .unwrap()
            .is_some()
    );
    let event = repo.data.audit.last().unwrap();
    assert_eq!(event.action, "admin_personal_token_revoked");
    assert_eq!(event.actor.as_str(), owner.id.as_str());
    assert_eq!(event.target.as_str(), sibling.credential_id().as_str());
}

#[test]
fn logout_and_personal_token_revoke_audit_failure_roll_back_revocation_and_cleanup() {
    for logout in [true, false] {
        let mut repo = MemoryRepository::new();
        let owner = bootstrap(&mut repo).unwrap();
        let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
        let pat = authenticated(&mut repo, &owner.id, AdminCredentialKind::PersonalToken);
        let account = repo.account_by_id(&owner.id).unwrap().unwrap();
        let stale = AdminCredential::issue(
            AdminCredentialId::parse(format!("crd_{:032x}", 99)).unwrap(),
            AdminCredentialKind::PersonalToken,
            AdminCredentialDigest::from_bytes([99; 32]),
            AdminCredentialBinding::for_account(&account, HumanAuthEpoch::from_bytes([9; 16])),
            900,
        )
        .unwrap()
        .snapshot();
        repo.data.credentials.insert(stale.id.clone(), stale);
        repo.fail_audit = true;
        let before = repo.data.clone();
        let result = if logout {
            LogoutAdminSession::execute(&mut repo, &actor, &Operation { fail: false })
        } else {
            RevokeOwnAdminPersonalToken::execute(
                &mut repo,
                &actor,
                &Operation { fail: false },
                pat.credential_id(),
            )
        };
        assert_eq!(result, Err(AdminAccessError::Unavailable));
        assert_eq!(repo.data, before);
    }
}

#[test]
fn foreign_corrupt_personal_token_records_remain_indistinguishable_from_missing_targets() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let mut other = AdminAccount::pending(
        AdminUserId::parse(format!("usr_{:032x}", 2)).unwrap(),
        AdminUsername::parse("other.user").unwrap(),
        AdminDisplayName::parse("Other").unwrap(),
        AdminRole::Viewer,
    );
    other
        .install_password(
            repo.data.accounts[&owner.id]
                .password_verifier
                .clone()
                .unwrap(),
        )
        .unwrap();
    let other_id = other.snapshot().id;
    repo.data
        .accounts
        .insert(other_id.clone(), other.snapshot());
    let foreign = authenticated(&mut repo, &other_id, AdminCredentialKind::PersonalToken);
    repo.data
        .credentials
        .get_mut(foreign.credential_id())
        .unwrap()
        .expires_at += 1;
    let before = repo.data.clone();
    assert_eq!(
        RevokeOwnAdminPersonalToken::execute(
            &mut repo,
            &actor,
            &Operation { fail: false },
            foreign.credential_id()
        ),
        Err(AdminAccessError::NotFound)
    );
    assert_eq!(repo.data, before);
}

#[test]
fn startup_cleanup_reclaims_at_most_128_per_purpose_without_deleting_current_future_accounts_or_audit()
 {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let pending = AdminAccount::pending(
        AdminUserId::parse(format!("usr_{:032x}", 2)).unwrap(),
        AdminUsername::parse("pending.user").unwrap(),
        AdminDisplayName::parse("Pending").unwrap(),
        AdminRole::Viewer,
    );
    // A pending account needs no verifier; this is a valid target for both grant purposes.
    repo.data
        .accounts
        .insert(pending.snapshot().id, pending.snapshot());
    let account = repo.account_by_id(&owner.id).unwrap().unwrap();
    for (index, kind) in [
        AdminCredentialKind::WebSession,
        AdminCredentialKind::PersonalToken,
        AdminCredentialKind::SetupGrant,
        AdminCredentialKind::ResetGrant,
    ]
    .into_iter()
    .enumerate()
    {
        let user = if kind.is_grant() { &pending } else { &account };
        for ordinal in 0_u128..132 {
            let id = (index as u128 + 1) * 1_000 + ordinal;
            let mut digest = [0; 32];
            digest[..16].copy_from_slice(&id.to_be_bytes());
            let credential = AdminCredential::issue(
                AdminCredentialId::parse(format!("crd_{id:032x}")).unwrap(),
                kind,
                AdminCredentialDigest::from_bytes(digest),
                AdminCredentialBinding::for_account(
                    user,
                    if ordinal < 130 {
                        HumanAuthEpoch::from_bytes([9; 16])
                    } else {
                        repo.data.auth.epoch
                    },
                ),
                if ordinal == 131 { 1_001 } else { 1_000 },
            )
            .unwrap()
            .snapshot();
            repo.data
                .credentials
                .insert(credential.id.clone(), credential);
        }
    }
    let accounts = repo.data.accounts.clone();
    let audit = repo.data.audit.clone();
    assert_eq!(
        CleanupAdminCredentialLookups::execute(&mut repo, &Operation { fail: false }).unwrap(),
        512
    );
    assert_eq!(repo.data.credentials.len(), 16);
    assert_eq!(
        CleanupAdminCredentialLookups::execute(&mut repo, &Operation { fail: false }).unwrap(),
        8
    );
    assert_eq!(
        CleanupAdminCredentialLookups::execute(&mut repo, &Operation { fail: false }).unwrap(),
        0
    );
    assert_eq!(repo.data.credentials.len(), 8);
    assert_eq!(repo.data.accounts, accounts);
    assert_eq!(repo.data.audit, audit);
    let before = repo.data.clone();
    assert_eq!(
        CleanupAdminCredentialLookups::execute(&mut repo, &Operation { fail: true }),
        Err(AdminAccessError::OperationExpired)
    );
    assert_eq!(repo.data, before);
}

#[test]
fn account_grant_issue_and_password_revocation_apply_bounded_lookup_cleanup() {
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let account = repo.account_by_id(&owner.id).unwrap().unwrap();
    let stale = AdminCredential::issue(
        AdminCredentialId::parse(format!("crd_{:032x}", 99)).unwrap(),
        AdminCredentialKind::PersonalToken,
        AdminCredentialDigest::from_bytes([99; 32]),
        AdminCredentialBinding::for_account(&account, HumanAuthEpoch::from_bytes([9; 16])),
        900,
    )
    .unwrap()
    .snapshot();
    let stale_id = stale.id.clone();
    repo.data.credentials.insert(stale.id.clone(), stale);
    let (passwords, generator) = dependencies(&repo);
    let created = CreateAdminAccount::execute(
        &mut repo,
        &actor,
        &Operation { fail: false },
        &passwords,
        &generator,
        CreateAdminAccountInput {
            username: AdminUsername::parse("new.user").unwrap(),
            display_name: AdminDisplayName::parse("New user").unwrap(),
            role: AdminRole::Viewer,
            current_password: "fixture current password",
        },
    )
    .unwrap();
    assert!(repo.credential_by_id(&stale_id).unwrap().is_none());
    ChangeOwnAdminPassword::execute(
        &mut repo,
        &actor,
        &Operation { fail: false },
        &passwords,
        ChangeOwnAdminPasswordInput {
            current_password: "fixture current password",
            new_password: "replacement fixture password",
        },
    )
    .unwrap();
    assert!(
        repo.credential_by_id(actor.credential_id())
            .unwrap()
            .is_none()
    );
    assert!(repo.credential_by_id(&created.setup.id).unwrap().is_some());
}
