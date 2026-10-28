//! Protected immutable catalog-reference Job creation and provenance mapping.

use super::*;
use fleet_application::catalog_execution::{
    CatalogRunbookJobQueryRepository, CatalogTargetError, GetCatalogRunbookJobProvenance,
    resolve_catalog_runbook_targets, validate_catalog_runbook_capability,
};
use fleet_application::{
    CatalogJobCreationStrategy, CatalogJobTargetSelection, CreateAuthorizedCatalogRunbookJob,
    CreateCatalogRunbookJobError, CreateCatalogRunbookJobInput,
};
use std::num::NonZeroU32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogRunbookJobRequest {
    job_id: String,
    source_id: String,
    commit: String,
    path: String,
    checksum: String,
    #[serde(default)]
    target_agent_ids: Vec<String>,
    #[serde(default)]
    selector: Option<String>,
    #[serde(default, rename = "matchLabels")]
    match_labels: Option<BTreeMap<String, String>>,
    #[serde(default)]
    strategy: Option<CatalogStrategyRequest>,
    #[serde(default = "default_drift_timeout_seconds")]
    timeout_seconds: u64,
    #[serde(default = "default_job_expiration_seconds")]
    expires_in_seconds: u64,
    #[serde(default)]
    confirmed_high_risk: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogStrategyRequest {
    #[serde(default)]
    concurrency: Option<NonZeroU32>,
    #[serde(default, rename = "maxFailures")]
    max_failures: Option<NonZeroU32>,
}

#[derive(Serialize)]
pub(super) struct CatalogProvenanceResponse {
    source_id: String,
    commit: String,
    path: String,
    checksum: String,
}

impl From<fleet_domain::CatalogRunbookProvenance> for CatalogProvenanceResponse {
    fn from(value: fleet_domain::CatalogRunbookProvenance) -> Self {
        Self {
            source_id: value.source_id().as_str().into(),
            commit: value.commit().as_str().into(),
            path: value.path().into(),
            checksum: value.checksum().into(),
        }
    }
}

#[derive(Serialize)]
pub(super) struct JobDetailResponse {
    #[serde(flatten)]
    pub summary: JobSummaryResponse,
    pub catalog_provenance: Option<CatalogProvenanceResponse>,
}

impl CatalogRunbookJobQueryRepository for ControllerStoreRef<'_> {
    type Error = fleet_store::StoreError;
    fn find_catalog_runbook_job_provenance(
        &self,
        job_id: &JobId,
    ) -> Result<Option<fleet_domain::CatalogRunbookProvenance>, Self::Error> {
        match self {
            Self::Sqlite(store) => store.find_catalog_runbook_job_provenance(job_id),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.borrow().find_catalog_runbook_job_provenance(job_id),
        }
    }
}

pub(super) fn job_provenance(
    store: ControllerStoreRef<'_>,
    job_id: &str,
) -> Result<Option<CatalogProvenanceResponse>, ControllerError> {
    let job_id = JobId::new(job_id).map_err(|_| ControllerError::Json("invalid job id".into()))?;
    GetCatalogRunbookJobProvenance::execute(&store, &job_id)
        .map(|value| value.map(Into::into))
        .map_err(|_| ControllerError::Json("catalog_job_provenance_unavailable".into()))
}

type HttpFailure = (u16, &'static str);

fn target_error(error: CatalogTargetError) -> HttpFailure {
    match error {
        CatalogTargetError::UnknownAgent | CatalogTargetError::DisabledAgent => {
            (409, "catalog_target_unavailable")
        }
        CatalogTargetError::UnsupportedCapability => (409, "catalog_target_unsupported"),
        CatalogTargetError::StaleCapability => (409, "catalog_target_capabilities_stale"),
        _ => (400, "invalid_catalog_targets"),
    }
}

fn creation_error<R, S>(error: CreateCatalogRunbookJobError<R, S>) -> HttpFailure {
    match error {
        CreateCatalogRunbookJobError::SourceNotFound
        | CreateCatalogRunbookJobError::RevisionNotFound
        | CreateCatalogRunbookJobError::DocumentNotFound => (404, "catalog_reference_not_found"),
        CreateCatalogRunbookJobError::RevisionNotActive
        | CreateCatalogRunbookJobError::RevisionNotReady
        | CreateCatalogRunbookJobError::ChecksumMismatch
        | CreateCatalogRunbookJobError::SelectionChanged => (409, "catalog_selection_changed"),
        CreateCatalogRunbookJobError::DuplicateJob => (409, "job_already_exists"),
        CreateCatalogRunbookJobError::Repository(_) | CreateCatalogRunbookJobError::Sign(_) => {
            (500, "catalog_job_creation_unavailable")
        }
        _ => (400, "invalid_catalog_job"),
    }
}

/// Authenticates, validates and commits before considering dispatch. Errors expose
/// classified codes only; uncertain POST responses must be reconciled by Job ID.
pub(super) fn create_http(request: &str, state: &ControllerAppState) -> String {
    match create(request, state) {
        Ok(body) => no_store(response(201, "application/json", &format!("{body}\n"))),
        Err((403, "forbidden_job_create")) => {
            no_store(forbidden_response(AdminPermission::JobCreate))
        }
        Err((403, "forbidden_catalog_read")) => {
            no_store(forbidden_response(AdminPermission::PolicyRead))
        }
        Err((status, code)) => {
            let output = no_store(response(
                status,
                "application/json",
                &format!("{{\"error\":\"{code}\"}}\n"),
            ));
            if status == 409
                && matches!(
                    code,
                    "catalog_selection_changed"
                        | "catalog_target_unavailable"
                        | "catalog_target_unsupported"
                        | "catalog_target_capabilities_stale"
                )
            {
                output.replacen(
                    "\r\n\r\n",
                    &format!("\r\nFleet-Catalog-Rejection: {code}\r\n\r\n"),
                    1,
                )
            } else {
                output
            }
        }
    }
}

fn create(request: &str, state: &ControllerAppState) -> Result<String, HttpFailure> {
    let unavailable = (500, "catalog_job_creation_unavailable");
    let invalid = (400, "invalid_catalog_job");
    let mut store = state.store.lock().map_err(|_| unavailable)?;
    let context = authenticate_admin_request_with_metadata(request, &*store, &state.metadata)
        .map_err(|_| unavailable)?
        .ok_or((401, "unauthorized"))?;
    // Both permissions are enforced here because this route owns a mutable-store
    // boundary outside the shared read-only fallback dispatcher.
    if !context.allows(AdminPermission::JobCreate) {
        return Err((403, "forbidden_job_create"));
    }
    if !context.allows(AdminPermission::PolicyRead) {
        return Err((403, "forbidden_catalog_read"));
    }
    if request
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        != Some("/api/jobs/catalog-runbook")
    {
        return Err(invalid);
    }
    let input: CatalogRunbookJobRequest =
        serde_json::from_str(request_body(request)).map_err(|_| invalid)?;
    let selection_count = usize::from(!input.target_agent_ids.is_empty())
        + usize::from(input.selector.is_some())
        + usize::from(input.match_labels.is_some());
    if selection_count > 1
        || input.timeout_seconds == 0
        || input.expires_in_seconds == 0
        || input
            .timeout_seconds
            .checked_mul(1000)
            .and_then(|v| i64::try_from(v).ok())
            .is_none()
    {
        return Err(invalid);
    }
    let selection = if !input.target_agent_ids.is_empty() {
        CatalogJobTargetSelection::ExplicitIds
    } else if let Some(value) = input.selector {
        CatalogJobTargetSelection::Selector(value)
    } else if let Some(value) = input.match_labels {
        CatalogJobTargetSelection::MatchLabels(value)
    } else {
        CatalogJobTargetSelection::Runbook
    };
    let source = CatalogSourceId::new(&input.source_id).map_err(|_| invalid)?;
    let commit = CatalogCommitId::new(&input.commit).map_err(|_| invalid)?;
    CatalogDocument::new(
        source.clone(),
        commit.clone(),
        fleet_domain::CatalogDocumentKind::Runbook,
        &input.path,
        &input.checksum,
    )
    .map_err(|_| invalid)?;
    let record = GetCatalogDocumentDetail::execute(&*store, &source, &commit, &input.path)
        .map_err(|_| unavailable)?
        .ok_or((404, "catalog_reference_not_found"))?;
    if record.document.kind() != fleet_domain::CatalogDocumentKind::Runbook {
        return Err(invalid);
    }
    let runbook = fleet_domain::parse_runbook_document(&record.body).map_err(|_| invalid)?;
    let inventory = ControllerAgentInventoryRepository {
        store: (&*store).into(),
    };
    let agents = ListInventoryAgents::execute(&inventory).map_err(|_| unavailable)?;
    let targets = resolve_catalog_runbook_targets(
        &agents,
        &selection,
        &input.target_agent_ids,
        &runbook.target_selector,
    )
    .map_err(target_error)?;
    let issued_at = SystemTime::now();
    let expires_at = issued_at
        .checked_add(Duration::from_secs(input.expires_in_seconds))
        .ok_or(invalid)?;
    if expires_at
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .is_none()
    {
        return Err(invalid);
    }
    for id in &targets {
        let snapshot = store
            .latest_agent_capability_snapshot(id)
            .map_err(|_| unavailable)?;
        validate_catalog_runbook_capability(snapshot, &runbook, issued_at).map_err(target_error)?;
    }
    let strategy = input
        .strategy
        .map(|s| CatalogJobCreationStrategy {
            concurrency: s.concurrency.unwrap_or(NonZeroU32::MIN),
            max_failures: s.max_failures,
        })
        .unwrap_or_default();
    let nonce = fleet_core::generate_prefixed_ulid("nonce").map_err(|_| unavailable)?;
    let approval = fleet_core::generate_prefixed_ulid("approval").map_err(|_| unavailable)?;
    let mut signer = ControllerTaskSigner {
        private_key: &state.identity.private_key,
        signing_fingerprint: &state.identity.fingerprint,
    };
    let job_id = input.job_id.clone();
    let owner = admin_password_worker::AdminAuthRequest::new(
        admin_crypto::AdminAuthSettings::new(1)
            .map_err(|error| admin_http::failure(error, "credential_limit"))?,
    )
    .map_err(|error| admin_http::failure(error, "credential_limit"))?;
    let output = CreateAuthorizedCatalogRunbookJob::execute(
        &mut *store,
        &context.principal,
        &owner.operation(),
        &mut signer,
        CreateCatalogRunbookJobInput {
            strategy,
            target_selection: selection,
            source_id: input.source_id,
            commit: input.commit,
            path: input.path,
            checksum: input.checksum,
            job_id: input.job_id,
            target_agent_ids: targets,
            timeout: Duration::from_secs(input.timeout_seconds),
            confirmed_high_risk: input.confirmed_high_risk,
            confirmed_by: context.actor_id.clone(),
            issued_at,
            expires_at,
            nonce_prefix: nonce,
            approval_request_id: approval,
            approval_expires_at: expires_at,
        },
    )
    .map_err(|error| match error {
        CreateCatalogRunbookJobError::Repository(
            fleet_application::AdminJobCommitError::Authorization(error),
        ) => admin_http::failure(error, "credential_limit"),
        CreateCatalogRunbookJobError::Repository(
            fleet_application::AdminJobCommitError::DuplicateJob,
        ) => (409, "job_already_exists"),
        error => creation_error(error),
    })?;
    let needs_approval = output.approval_request.is_some();
    let result = serde_json::to_string(&CreateRunbookJobResponse {
        job_id: job_id.clone(),
        target_count: output.targets.len(),
        assignment_count: output.envelopes.len(),
        status: if needs_approval {
            "pending_approval"
        } else {
            "queued"
        }
        .into(),
        approval_request_id: output.approval_request.map(|a| a.id),
    })
    .map_err(|_| unavailable)?;
    // No socket write occurs while preparing or persisting the creation bundle.
    // The existing dispatcher rechecks canonical approval/expiry/session state.
    drop(store);
    if !needs_approval {
        let store = state.store.lock().map_err(|_| unavailable)?;
        dispatch_pending_assignments_for_created_job(&*store, &state.sessions, &job_id)
            .map_err(|_| unavailable)?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::create_http;
    use fleet_application::{AgentRepository, CatalogRepository};
    use fleet_domain::{CatalogDocumentKind, CatalogReference, PublicCatalogUrl};

    const BODY: &str = "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nname: sample\nselector: role=web\nsteps:\n  - id: collect\n    facts.collect:\n";

    struct TestRoot(PathBuf);
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn state() -> (ControllerAppState, TestRoot) {
        state_with_role("operator")
    }
    fn state_with_role(role: &str) -> (ControllerAppState, TestRoot) {
        let root = std::env::temp_dir().join(format!(
            "fleet-catalog-http-{}",
            fleet_core::generate_prefixed_ulid("test").unwrap()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut store = SqliteStore::in_memory().unwrap();
        store
            .insert_admin_token_hash_with_identity(&hash_token("test-token"), "operator-real", role)
            .unwrap();
        let mut agent = Agent::new(
            AgentId::new("agent-a").unwrap(),
            AgentName::new("test-a").unwrap(),
            AgentIdentity {
                public_key: AgentPublicKey::new("test-public").unwrap(),
                fingerprint: AgentFingerprint::new("0123456789abcdef").unwrap(),
            },
        );
        agent.set_labels(vec![AgentLabel::new("role", "web").unwrap()]);
        AgentRepository::save(&mut store, agent).unwrap();
        let mut source = CatalogSource::new(
            CatalogSourceId::new("source-a").unwrap(),
            PublicCatalogUrl::new("https://example.com/catalog.git").unwrap(),
            CatalogReference::new("main").unwrap(),
        );
        let mut revision = source.begin_sync(CatalogCommitId::new("a".repeat(40)).unwrap());
        revision.begin_validation().unwrap();
        revision.mark_ready(1).unwrap();
        source.activate(&revision).unwrap();
        store.save_catalog_source(source.clone()).unwrap();
        store.save_catalog_revision(revision).unwrap();
        store
            .save_catalog_document(
                CatalogDocument::new(
                    source.id().clone(),
                    CatalogCommitId::new("a".repeat(40)).unwrap(),
                    CatalogDocumentKind::Runbook,
                    "runbooks/sample.yaml",
                    "c".repeat(64),
                )
                .unwrap(),
                BODY.into(),
            )
            .unwrap();
        (
            ControllerAppState {
                admin_auth: None,
                store: Arc::new(Mutex::new(ControllerStore::sqlite(store))),
                artifact_store: Arc::new(Mutex::new(LocalArtifactStore::new(&root).unwrap())),
                identity: Arc::new(ControllerIdentity::dev_insecure()),
                metadata: Arc::new(ControllerRuntimeMetadata::default()),
                sessions: Arc::new(Mutex::new(AgentSessionRegistry::default())),
                catalog_sync_submitter: None,
            },
            TestRoot(root),
        )
    }

    fn input() -> serde_json::Value {
        serde_json::json!({"job_id":"catalog-job-a","source_id":"source-a","commit":"a".repeat(40),
            "path":"runbooks/sample.yaml","checksum":"c".repeat(64),"target_agent_ids":["agent-a"],"confirmed_high_risk":true})
    }

    async fn post(
        state: &ControllerAppState,
        token: &str,
        body: serde_json::Value,
    ) -> (u16, serde_json::Value, HeaderMap) {
        let mut headers = HeaderMap::new();
        if !token.is_empty() {
            headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        }
        let mut request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/jobs/catalog-runbook")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        *request.headers_mut() = headers;
        let result = axum_http_fallback(State(state.clone()), request).await;
        let status = result.status().as_u16();
        let headers = result.headers().clone();
        let bytes = axum::body::to_bytes(result.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap(), headers)
    }

    #[tokio::test]
    async fn catalog_execution_http_creates_from_server_body_and_waits_for_approval() {
        let (state, root) = state();
        assert!(
            fleet_domain::parse_runbook_document(BODY).is_ok(),
            "valid durable fixture"
        );
        let (sender, mut receiver) = mpsc::channel(8);
        state
            .sessions
            .lock()
            .unwrap()
            .register(AgentSessionHandle::new(
                "agent-a",
                "test-session",
                SystemTime::now(),
                vec!["runbook_execution".into()],
                sender,
                Some(8),
            ));
        let (status, body, headers) = post(&state, "test-token", input()).await;
        assert_eq!(status, 201, "{body}");
        assert_eq!(body["status"], "pending_approval");
        assert_eq!(headers.get("cache-control").unwrap(), "no-store");
        let guard = state.store.lock().unwrap();
        #[cfg(not(feature = "postgres"))]
        let ControllerStore::Sqlite(sqlite) = &*guard;
        #[cfg(feature = "postgres")]
        let sqlite = match &*guard {
            ControllerStore::Sqlite(sqlite) => sqlite,
            ControllerStore::Postgres(_) => unreachable!("SQLite fixture"),
        };
        let job = sqlite.find_job_summary("catalog-job-a").unwrap().unwrap();
        assert_eq!(job.target_count, 1);
        let approvals = sqlite.list_approval_requests(None, 100).unwrap();
        assert_eq!(approvals[0].requester, "operator-real");
        assert!(
            sqlite
                .list_pending_runbook_assignments_for_agent("agent-a")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            sqlite
                .list_audit_events_by_category(AuditCategory::Job, 100)
                .unwrap()
                .len(),
            1
        );
        assert!(
            receiver.try_recv().is_err(),
            "pending approval must not send a task to the active session"
        );
        let approver = authenticate_admin_request_with_metadata(
            "POST /api/approvals/fixture/approve HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n",
            &*guard,
            &state.metadata,
        ).unwrap().unwrap();
        assert!(approve_approval(&approvals[0].id, "{}", &*guard, &approver).is_ok());
        let pending = sqlite
            .list_pending_runbook_assignments_for_agent("agent-a")
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].runbook.runbook_document(), BODY);
        assert!(pending[0].envelope.signature.is_some());
        drop(guard);
        drop(state);
        drop(root);
    }

    fn assert_no_creation(state: &ControllerAppState) {
        let store = state.store.lock().unwrap();
        assert!(
            store
                .store_ref()
                .find_job_summary("catalog-job-a")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .store_ref()
                .list_approval_requests(None, 100)
                .unwrap()
                .is_empty()
        );
        match &*store {
            ControllerStore::Sqlite(sqlite) => {
                assert!(sqlite.list_audit_events(100).unwrap().is_empty())
            }
            #[cfg(feature = "postgres")]
            _ => unreachable!(),
        }
    }

    #[test]
    fn catalog_execution_rejects_duplicate_dto_fields_and_query_before_writes() {
        let (state, root) = state();
        let body = input().to_string();
        let duplicate = body.replacen('{', "{\"job_id\":\"untrusted-id\",", 1);
        for (path, body) in [
            ("/api/jobs/catalog-runbook", duplicate.as_str()),
            ("/api/jobs/catalog-runbook?unexpected=1", body.as_str()),
        ] {
            let result = create_http(
                &format!("POST {path} HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n{body}"),
                &state,
            );
            assert!(result.starts_with("HTTP/1.1 400"));
            assert!(result.contains("Cache-Control: no-store"));
            assert_no_creation(&state);
        }
        drop(state);
        drop(root);
    }

    #[test]
    fn catalog_execution_openapi_and_detail_contract_match_the_additive_surface() {
        let document: serde_json::Value = serde_json::from_str(OPENAPI_JSON).unwrap();
        assert_eq!(
            document["paths"]["/api/jobs/catalog-runbook"]["post"]["responses"]["409"]["headers"]["Fleet-Catalog-Rejection"]
                ["schema"]["enum"],
            serde_json::json!([
                "catalog_selection_changed",
                "catalog_target_unavailable",
                "catalog_target_unsupported",
                "catalog_target_capabilities_stale"
            ])
        );
        let request = &document["components"]["schemas"]["CatalogRunbookJobRequest"];
        assert_eq!(request["additionalProperties"], false);
        for forbidden in [
            "runbook_document",
            "actor",
            "confirmed_by",
            "nonce_prefix",
            "approval_request_id",
        ] {
            assert!(request["properties"].get(forbidden).is_none());
        }
        assert_eq!(
            document["paths"]["/api/jobs/{job_id}"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/JobDetail"
        );
        assert_eq!(
            document["components"]["schemas"]["JobDetail"]["allOf"][1]["required"],
            serde_json::json!(["catalog_provenance"])
        );
    }

    #[tokio::test]
    async fn catalog_execution_http_rejects_auth_spoofing_and_ambiguous_inputs_without_writes() {
        let (state, root) = state();
        for (token, status) in [("", 401), ("bad-token", 401)] {
            let (actual, body, headers) = post(&state, token, input()).await;
            assert_eq!(actual, status);
            assert_eq!(headers.get("cache-control").unwrap(), "no-store");
            if status == 403 {
                assert_eq!(body["required_permission"], "job_create");
            }
            assert_no_creation(&state);
        }
        let (viewer, viewer_root) = state_with_role("viewer");
        let (status, error, headers) = post(&viewer, "test-token", input()).await;
        assert_eq!(status, 403);
        assert_eq!(error["required_permission"], "job_create");
        assert_eq!(headers.get("cache-control").unwrap(), "no-store");
        assert_no_creation(&viewer);
        drop(viewer);
        drop(viewer_root);
        let cases = [
            ("runbook_document", serde_json::json!("untrusted-body")),
            ("confirmed_by", serde_json::json!("owner-spoof")),
            ("actor", serde_json::json!("owner-spoof")),
            ("approval_request_id", serde_json::json!("approved")),
            ("nonce_prefix", serde_json::json!("reused")),
            ("selector", serde_json::json!("role=web")),
            ("matchLabels", serde_json::json!({"role":"web"})),
            ("strategy", serde_json::json!({"concurrency":0})),
            ("strategy", serde_json::json!({"maxFailures":0})),
            ("strategy", serde_json::json!({"actor":"spoof"})),
            ("timeout_seconds", serde_json::json!(0)),
            ("timeout_seconds", serde_json::json!(u64::MAX)),
            ("expires_in_seconds", serde_json::json!(0)),
            ("expires_in_seconds", serde_json::json!(u64::MAX)),
            ("path", serde_json::json!("../private.yaml")),
            ("commit", serde_json::json!("main")),
            ("checksum", serde_json::json!("invalid")),
            (
                "target_agent_ids",
                serde_json::json!(["agent-a", "agent-a"]),
            ),
        ];
        for (key, value) in cases {
            let mut body = input();
            body[key] = value;
            let (status, error, headers) = post(&state, "test-token", body).await;
            assert_eq!(status, 400, "{key}: {error}");
            assert_eq!(headers.get("cache-control").unwrap(), "no-store");
            assert_no_creation(&state);
        }
        drop(state);
        drop(root);
    }

    #[tokio::test]
    async fn catalog_execution_http_rejects_missing_stale_and_ineligible_targets_without_writes() {
        let (state, root) = state();
        for (key, value, status, code) in [
            (
                "source_id",
                serde_json::json!("missing"),
                404,
                "catalog_reference_not_found",
            ),
            (
                "path",
                serde_json::json!("runbooks/missing.yaml"),
                404,
                "catalog_reference_not_found",
            ),
            (
                "checksum",
                serde_json::json!("d".repeat(64)),
                409,
                "catalog_selection_changed",
            ),
            (
                "target_agent_ids",
                serde_json::json!(["missing"]),
                409,
                "catalog_target_unavailable",
            ),
        ] {
            let mut body = input();
            body[key] = value;
            let (actual, error, headers) = post(&state, "test-token", body).await;
            assert_eq!((actual, error["error"].as_str().unwrap()), (status, code));
            assert_eq!(
                headers
                    .get("Fleet-Catalog-Rejection")
                    .map(|value| value.to_str().unwrap()),
                (status == 409).then_some(code)
            );
            assert_no_creation(&state);
        }
        {
            let store = state.store.lock().unwrap();
            store
                .save_agent_capability_snapshot(
                    &AgentId::new("agent-a").unwrap(),
                    AgentCapabilitySnapshot::reported(
                        AgentRuntimeProfile::new(
                            PrivilegeLevel::Unprivileged,
                            None,
                            None,
                            vec![AgentCapability::CommandExecution],
                        ),
                        SystemTime::now(),
                    ),
                )
                .unwrap();
        }
        let (status, error, _) = post(&state, "test-token", input()).await;
        assert_eq!(status, 409);
        assert_eq!(error["error"], "catalog_target_unsupported");
        assert_no_creation(&state);
        drop(state);
        drop(root);
    }

    #[tokio::test]
    async fn catalog_execution_http_checks_disabled_and_stale_targets_before_creation() {
        for disabled in [true, false] {
            let (state, root) = state();
            {
                let store = state.store.lock().unwrap();
                if disabled {
                    store.store_ref().revoke_agent_key("agent-a").unwrap();
                } else {
                    store
                        .save_agent_capability_snapshot(
                            &AgentId::new("agent-a").unwrap(),
                            AgentCapabilitySnapshot::reported(
                                AgentRuntimeProfile::new(
                                    PrivilegeLevel::Unprivileged,
                                    None,
                                    None,
                                    vec![AgentCapability::RunbookExecution],
                                ),
                                UNIX_EPOCH,
                            ),
                        )
                        .unwrap();
                }
            }
            let (status, error, _) = post(&state, "test-token", input()).await;
            assert_eq!(status, 409);
            assert_eq!(
                error["error"],
                if disabled {
                    "catalog_target_unavailable"
                } else {
                    "catalog_target_capabilities_stale"
                }
            );
            assert_no_creation(&state);
            drop(state);
            drop(root);
        }
    }

    #[tokio::test]
    async fn catalog_execution_http_signer_failure_is_safe_and_leaves_no_creation_or_dispatch() {
        let (mut state, root) = state();
        Arc::make_mut(&mut state.identity).private_key = "not-a-private-key-fixture".into();
        let (status, error, headers) = post(&state, "test-token", input()).await;
        assert_eq!(status, 500);
        assert_eq!(
            error,
            serde_json::json!({"error":"catalog_job_creation_unavailable"})
        );
        assert_eq!(headers.get("cache-control").unwrap(), "no-store");
        assert_no_creation(&state);
        drop(state);
        drop(root);
    }

    #[tokio::test]
    async fn catalog_execution_http_uses_document_selector_and_keeps_raw_detail_compatible() {
        let (state, root) = state();
        let mut body = input();
        body.as_object_mut().unwrap().remove("target_agent_ids");
        let (status, created, _) = post(&state, "test-token", body).await;
        assert_eq!(status, 201, "{created}");
        {
            let store = state.store.lock().unwrap();
            let detail: serde_json::Value =
                serde_json::from_str(&get_job("catalog-job-a", &*store, None).unwrap().unwrap())
                    .unwrap();
            assert_eq!(detail["selector_kind"], "runbook_matchLabels");
            let raw = serde_json::json!({"job_id":"raw-job-a","target_agent_ids":["agent-a"],"program":"whoami","timeout_seconds":30,"confirmed_high_risk":false});
            let context = authenticate_admin_request(
                "GET /api/agents HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n",
                &*store,
            )
            .unwrap()
            .unwrap();
            assert!(
                create_command_job(&raw.to_string(), &*store, &state.identity, &context).is_ok()
            );
            let raw: serde_json::Value =
                serde_json::from_str(&get_job("raw-job-a", &*store, None).unwrap().unwrap())
                    .unwrap();
            assert!(raw["catalog_provenance"].is_null());
            assert_eq!(raw["id"], "raw-job-a");
            assert_eq!(raw["command_program"], "whoami");
            assert!(get_job("missing-job", &*store, None).unwrap().is_none());
        }
        drop(state);
        drop(root);
    }

    #[tokio::test]
    async fn catalog_execution_http_duplicate_and_later_activation_preserve_provenance_and_body() {
        let (state, root) = state();
        let (status, created, _) = post(&state, "test-token", input()).await;
        assert_eq!(status, 201, "{created}");
        let (status, duplicate, duplicate_headers) = post(&state, "test-token", input()).await;
        assert_eq!(status, 409);
        assert_eq!(duplicate["error"], "job_already_exists");
        assert!(duplicate_headers.get("Fleet-Catalog-Rejection").is_none());
        {
            let mut store = state.store.lock().unwrap();
            let source_id = CatalogSourceId::new("source-a").unwrap();
            let mut source = store.find_catalog_source(&source_id).unwrap().unwrap();
            let mut revision = source.begin_sync(CatalogCommitId::new("b".repeat(40)).unwrap());
            revision.begin_validation().unwrap();
            revision.mark_ready(1).unwrap();
            source.activate(&revision).unwrap();
            store.save_catalog_revision(revision.clone()).unwrap();
            store.activate_catalog_revision(source, &revision).unwrap();
            let detail: serde_json::Value =
                serde_json::from_str(&get_job("catalog-job-a", &*store, None).unwrap().unwrap())
                    .unwrap();
            assert_eq!(
                detail["catalog_provenance"],
                serde_json::json!({"source_id":"source-a","commit":"a".repeat(40),"path":"runbooks/sample.yaml","checksum":"c".repeat(64)})
            );
            assert_eq!(
                store
                    .store_ref()
                    .list_approval_requests(None, 100)
                    .unwrap()
                    .len(),
                1
            );
        }
        let mut next = input();
        next["job_id"] = serde_json::json!("catalog-job-b");
        let (status, error, _) = post(&state, "test-token", next).await;
        assert_eq!(status, 409);
        assert_eq!(error["error"], "catalog_selection_changed");
        drop(state);
        drop(root);
    }

    #[test]
    fn catalog_execution_route_requires_job_create_permission() {
        assert_eq!(
            required_permission_for_route("POST", "/api/jobs/catalog-runbook"),
            Some(AdminPermission::JobCreate)
        );
    }
}
