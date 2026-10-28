//! Fresh business permission decisions from canonical credential/account/mode state.

use super::*;

#[test]
fn canonical_write_guard_rejects_expiry_reached_during_its_own_final_clock_check() {
    struct Edge {
        calls: Cell<usize>,
        expires: i64,
    }
    impl AdminOperation for Edge {
        fn checked_now(&self) -> Result<i64, AdminAccessError> {
            let n = self.calls.get();
            self.calls.set(n + 1);
            Ok(if n == 0 {
                self.expires - 1
            } else {
                self.expires
            })
        }
    }
    let mut repo = MemoryRepository::new();
    let owner = bootstrap(&mut repo).unwrap();
    let actor = authenticated(&mut repo, &owner.id, AdminCredentialKind::WebSession);
    let expires = repo.data.credentials[actor.credential_id()].expires_at;
    assert_eq!(
        AuthorizeAdminWrite::execute(
            &repo,
            &AdminMutationPrincipal::personal(actor),
            &Edge {
                calls: Cell::new(0),
                expires
            },
            AdminPermission::JobCreate
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
}

#[test]
fn authorized_command_rejects_clock_rollback_between_preparation_and_canonical_check() {
    use crate::{
        AdminCommandCommitError, AdminCommandJobRepository, CommandCreationMetadata,
        CreateAuthorizedCommandJob, CreateAuthorizedCommandJobError, CreateCommandJobInput,
        PreparedCommandJob, TaskEnvelopeSigner,
    };
    struct Timeline(Cell<usize>);
    impl AdminOperation for Timeline {
        fn checked_now(&self) -> Result<i64, AdminAccessError> {
            let n = self.0.get();
            self.0.set(n + 1);
            Ok(if n == 1 { 1_001 } else { 1_000 })
        }
    }
    struct Signer;
    impl TaskEnvelopeSigner for Signer {
        type Error = &'static str;
        fn sign(&mut self, _: &str) -> Result<String, Self::Error> {
            Ok("fixture-signature".to_owned())
        }
    }
    struct Repository {
        identity: MemoryRepository,
        committed: bool,
    }
    impl AdminCommandJobRepository for Repository {
        type Error = &'static str;
        fn commit_admin_command_job(
            &mut self,
            principal: &AdminMutationPrincipal,
            operation: &dyn AdminOperation,
            creation: &PreparedCommandJob,
            _: &CommandCreationMetadata,
        ) -> Result<(), AdminCommandCommitError<Self::Error>> {
            creation
                .authorize(&self.identity, principal, operation)
                .map_err(AdminCommandCommitError::Authorization)?;
            self.committed = true;
            Ok(())
        }
    }
    let mut identity = MemoryRepository::new();
    let owner = bootstrap(&mut identity).unwrap();
    let actor = authenticated(&mut identity, &owner.id, AdminCredentialKind::WebSession);
    let mut repository = Repository {
        identity,
        committed: false,
    };
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let result = CreateAuthorizedCommandJob::execute(
        &mut repository,
        &AdminMutationPrincipal::personal(actor),
        &Timeline(Cell::new(0)),
        &mut Signer,
        CreateCommandJobInput {
            job_id: "clock-command".to_owned(),
            target_agent_ids: vec!["agent-clock".to_owned()],
            program: "uptime".to_owned(),
            args: Vec::new(),
            timeout: Duration::from_secs(30),
            confirmed_high_risk: false,
            confirmed_by: "spoof".to_owned(),
            issued_at: now,
            expires_at: now + Duration::from_secs(60),
            nonce_prefix: "clock".to_owned(),
            approval_request_id: "clock-approval".to_owned(),
            approval_expires_at: now + Duration::from_secs(60),
        },
        &CommandCreationMetadata::new(1, None, "explicit_ids", "[\"agent-clock\"]".to_owned())
            .unwrap(),
    );
    assert!(matches!(
        result,
        Err(CreateAuthorizedCommandJobError::Commit(
            AdminCommandCommitError::Authorization(AdminAccessError::OperationExpired)
        ))
    ));
    assert!(!repository.committed);
}

#[test]
fn canonical_write_guard_uses_current_personal_binding_permission_and_fixed_time() {
    struct At(i64);
    impl AdminOperation for At {
        fn checked_now(&self) -> Result<i64, AdminAccessError> {
            Ok(self.0)
        }
    }
    for kind in [
        AdminCredentialKind::WebSession,
        AdminCredentialKind::PersonalToken,
    ] {
        for case in 0..6 {
            let mut repo = MemoryRepository::new();
            bootstrap(&mut repo).unwrap();
            let user = add_active(&mut repo, AdminRole::Operator);
            let actor = authenticated(&mut repo, &user, kind);
            let principal = AdminMutationPrincipal::personal(actor.clone());
            let now = At(1_000);
            assert_eq!(
                AuthorizeAdminWrite::execute(&repo, &principal, &now, AdminPermission::JobCreate)
                    .unwrap()
                    .as_str(),
                user.as_str()
            );
            let expires = repo.data.credentials[actor.credential_id()].expires_at;
            match case {
                0 => {
                    let row = repo
                        .data
                        .credentials
                        .get_mut(actor.credential_id())
                        .unwrap();
                    row.state = AdminCredentialState::Revoked;
                    row.ended_at = Some(1_000);
                }
                1 => {
                    repo.data.accounts.get_mut(&user).unwrap().status = AdminAccountStatus::Disabled
                }
                2 => repo.data.auth.epoch = HumanAuthEpoch::from_bytes([77; 16]),
                3 => repo.data.auth.mode = AdminAuthMode::LocalSetupRequired,
                4 => {
                    let mut account =
                        AdminAccount::from_snapshot(repo.data.accounts[&user].clone()).unwrap();
                    account.change_role(AdminRole::Viewer, 1).unwrap();
                    repo.data.accounts.insert(user.clone(), account.snapshot());
                }
                _ => {}
            }
            let before = repo.data.clone();
            assert_eq!(
                AuthorizeAdminWrite::execute(
                    &repo,
                    &principal,
                    &At(if case == 5 { expires } else { 1_000 }),
                    AdminPermission::JobCreate
                )
                .unwrap_err(),
                AdminAccessError::Unauthorized
            );
            assert_eq!(repo.data, before);
        }
    }
    let mut repo = MemoryRepository::new();
    bootstrap(&mut repo).unwrap();
    let viewer = add_active(&mut repo, AdminRole::Viewer);
    let principal = AdminMutationPrincipal::personal(authenticated(
        &mut repo,
        &viewer,
        AdminCredentialKind::WebSession,
    ));
    assert_eq!(
        AuthorizeAdminWrite::execute(&repo, &principal, &At(1_000), AdminPermission::JobCreate)
            .unwrap_err(),
        AdminAccessError::Forbidden
    );
    assert!(
        AuthorizeAdminWrite::execute(&repo, &principal, &At(1_000), AdminPermission::JobRead)
            .is_ok()
    );
    assert_eq!(
        AuthorizeAdminWrite::execute(
            &repo,
            &principal,
            &Operation { fail: true },
            AdminPermission::JobRead
        )
        .unwrap_err(),
        AdminAccessError::OperationExpired
    );
}

#[test]
fn canonical_write_guard_reloads_legacy_hash_actor_role_and_mode_without_personal_fallback() {
    let digest = "ab".repeat(32);
    let record = crate::AdminTokenRecord {
        actor_id: "fixture-legacy".to_owned(),
        role: "owner".to_owned(),
    };
    let principal = AdminMutationPrincipal::legacy(&digest, &record).unwrap();
    assert!(!format!("{principal:?}").contains(&digest));
    let mut repo = MemoryRepository::new();
    repo.data.legacy_admin = Some((digest.clone(), record.clone()));
    assert_eq!(
        AuthorizeAdminWrite::execute(
            &repo,
            &principal,
            &Operation { fail: false },
            AdminPermission::JobCreate
        )
        .unwrap()
        .as_str(),
        record.actor_id
    );
    repo.data.legacy_admin.as_mut().unwrap().1.role = "viewer".to_owned();
    assert_eq!(
        AuthorizeAdminWrite::execute(
            &repo,
            &principal,
            &Operation { fail: false },
            AdminPermission::JobCreate
        )
        .unwrap_err(),
        AdminAccessError::Forbidden
    );
    repo.data.legacy_admin.as_mut().unwrap().1.role = "owner".to_owned();
    repo.data.legacy_admin.as_mut().unwrap().1.actor_id = "changed-actor".to_owned();
    assert_eq!(
        AuthorizeAdminWrite::execute(
            &repo,
            &principal,
            &Operation { fail: false },
            AdminPermission::JobCreate
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
    repo.data.legacy_admin = Some((digest, record));
    repo.data.auth.mode = AdminAuthMode::Personal;
    assert_eq!(
        AuthorizeAdminWrite::execute(
            &repo,
            &principal,
            &Operation { fail: false },
            AdminPermission::JobCreate
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
}
