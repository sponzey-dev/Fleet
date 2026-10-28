//! Human HTTP credentials and same-origin adapters. Application use cases own identity
//! effects; bootstrap owns the CPU worker and every request owns cancellation/admission.

use super::*;
use crate::admin_crypto::{AdminAuthSettings, AdminTokenCrypto};
use crate::admin_identity_store::SharedIdentityRepository;
use crate::admin_password_worker::{
    AdminAuthOperation, AdminAuthRequest, AdminPasswordClient, AdminPasswordWorker,
};
use fleet_application::admin_identity::*;
use fleet_domain::{AdminAccountStatus, AdminAuthMode, AdminCredentialKind, AdminUsername};
use hmac::{Hmac, Mac};
use std::collections::HashMap;
use std::time::Instant;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

#[path = "admin_account_http.rs"]
mod accounts;

#[path = "admin_self_http.rs"]
mod credentials;

#[path = "admin_metadata_http.rs"]
mod metadata;

#[cfg(test)]
#[path = "admin_http_contract_tests.rs"]
mod tests;

pub(super) const BODY_LIMIT: usize = 16 * 1024;

#[derive(Clone)]
pub(super) struct CookiePolicy {
    origin: String,
    secure: bool,
}

impl CookiePolicy {
    pub(super) fn parse(external_url: Option<&str>) -> Result<Self, AdminAccessError> {
        let raw = external_url.ok_or(AdminAccessError::Unavailable)?;
        let url = url::Url::parse(raw).map_err(|_| AdminAccessError::Unavailable)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url
                .host_str()
                .is_none_or(|host| host.contains('*') || matches!(host, "0.0.0.0" | "[::]" | "::"))
        {
            return Err(AdminAccessError::Unavailable);
        }
        Ok(Self {
            origin: url.origin().ascii_serialization(),
            secure: url.scheme() == "https",
        })
    }

    fn name(&self) -> &'static str {
        if self.secure {
            "__Host-fleet_session"
        } else {
            "fleet_session"
        }
    }
    fn cookie(&self, secret: &str, max_age: u32) -> String {
        format!(
            "{}={secret}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
            self.name(),
            if self.secure { "; Secure" } else { "" }
        )
    }
    fn require_origin(&self, headers: &RequestHeaders<'_>) -> Result<(), HttpFailure> {
        if headers.unique("origin")? != Some(self.origin.as_str()) {
            return Err((403, "forbidden_origin"));
        }
        Ok(())
    }
}

type HttpFailure = (u16, &'static str);

/// Headers are read only before the first empty line; body text can never be a credential.
pub(super) struct RequestHeaders<'a> {
    head: &'a str,
}

impl<'a> RequestHeaders<'a> {
    pub(super) fn parse(request: &'a str) -> Result<Self, HttpFailure> {
        let (head, _) = request
            .split_once("\r\n\r\n")
            .ok_or((400, "invalid_request"))?;
        if head
            .lines()
            .skip(1)
            .any(|line| line.starts_with([' ', '\t']) || !line.contains(':'))
        {
            return Err((400, "invalid_request"));
        }
        Ok(Self { head })
    }
    fn unique(&self, field: &str) -> Result<Option<&'a str>, HttpFailure> {
        let mut values = self.head.lines().skip(1).filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(field)
                .then_some(value.trim_matches([' ', '\t']))
        });
        let value = values.next();
        if values.next().is_some() {
            return Err((400, "ambiguous_authentication"));
        }
        Ok(value)
    }
    fn credential(
        &self,
        policy: &CookiePolicy,
    ) -> Result<Option<HumanCredential<'a>>, HttpFailure> {
        match self.raw_credential()? {
            Some(RawHumanCredential::Cookie { name, raw }) => {
                if name != policy.name() {
                    return Err((401, "unauthorized"));
                }
                Ok(Some(HumanCredential {
                    kind: AdminCredentialKind::WebSession,
                    raw,
                }))
            }
            Some(RawHumanCredential::Bearer(raw)) => Ok(Some(HumanCredential {
                kind: AdminCredentialKind::PersonalToken,
                raw,
            })),
            None => Ok(None),
        }
    }

    fn raw_credential(&self) -> Result<Option<RawHumanCredential<'a>>, HttpFailure> {
        let bearer = self.unique("authorization")?;
        let mut cookie = None;
        if let Some(cookies) = self.unique("cookie")? {
            for item in cookies.split(';') {
                let Some((name, value)) = item.trim().split_once('=') else {
                    continue;
                };
                if matches!(name, "fleet_session" | "__Host-fleet_session") {
                    if cookie.is_some() {
                        return Err((400, "ambiguous_authentication"));
                    }
                    cookie = Some((name, value));
                }
            }
        }
        if bearer.is_some() && cookie.is_some() {
            return Err((400, "ambiguous_authentication"));
        }
        if let Some((name, raw)) = cookie {
            return Ok(Some(RawHumanCredential::Cookie { name, raw }));
        }
        if let Some(value) = bearer {
            let (scheme, raw) = value.split_once(' ').ok_or((401, "unauthorized"))?;
            if !scheme.eq_ignore_ascii_case("bearer")
                || raw.is_empty()
                || raw.contains(char::is_whitespace)
            {
                return Err((401, "unauthorized"));
            }
            return Ok(Some(RawHumanCredential::Bearer(raw)));
        }
        Ok(None)
    }
}

enum RawHumanCredential<'a> {
    Cookie { name: &'a str, raw: &'a str },
    Bearer(&'a str),
}

struct HumanCredential<'a> {
    kind: AdminCredentialKind,
    raw: &'a str,
}

fn csrf(secret: &str) -> Result<String, HttpFailure> {
    // Fixed protocol-purpose message; the full 256-bit session secret is the HMAC key.
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| (503, "authentication_unavailable"))?;
    mac.update(b"fleet-human-session-csrf-v1\0");
    Ok(mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(Default)]
struct FailureLimiter {
    entries: HashMap<String, FailureWindow>,
}
struct FailureWindow {
    began: Instant,
    failures: usize,
    in_flight: usize,
}
struct LoginAttempt {
    limiter: Arc<Mutex<FailureLimiter>>,
    key: String,
}

impl FailureLimiter {
    fn reserve(limiter: &Arc<Mutex<Self>>, username: &str) -> Result<LoginAttempt, HttpFailure> {
        Self::reserve_at(limiter, username, Instant::now())
    }
    fn reserve_at(
        limiter: &Arc<Mutex<Self>>,
        username: &str,
        now: Instant,
    ) -> Result<LoginAttempt, HttpFailure> {
        let key = AdminUsername::parse(username)
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|_| "<invalid>".to_owned());
        let mut state = limiter
            .lock()
            .map_err(|_| (503, "authentication_unavailable"))?;
        state.entries.retain(|_, window| {
            window.in_flight > 0 || now.duration_since(window.began) < Duration::from_secs(300)
        });
        if !state.entries.contains_key(&key) && state.entries.len() >= 512 {
            return Err((429, "authentication_busy"));
        }
        let entry = state.entries.entry(key.clone()).or_insert(FailureWindow {
            began: now,
            failures: 0,
            in_flight: 0,
        });
        if entry.failures + entry.in_flight >= 5 {
            return Err((429, "authentication_busy"));
        }
        entry.in_flight += 1;
        Ok(LoginAttempt {
            limiter: limiter.clone(),
            key,
        })
    }
}
impl LoginAttempt {
    fn failed(&self) {
        if let Ok(mut state) = self.limiter.lock()
            && let Some(entry) = state.entries.get_mut(&self.key)
        {
            entry.failures += 1;
        }
    }
}
impl Drop for LoginAttempt {
    fn drop(&mut self) {
        if let Ok(mut state) = self.limiter.lock()
            && let Some(entry) = state.entries.get_mut(&self.key)
        {
            entry.in_flight = entry.in_flight.saturating_sub(1);
        }
    }
}

pub(super) struct AdminHttpRuntime {
    settings: AdminAuthSettings,
    policy: Option<CookiePolicy>,
    client: Option<AdminPasswordClient>,
    admission: Arc<tokio::sync::Semaphore>,
    failures: Arc<Mutex<FailureLimiter>>,
}

impl AdminHttpRuntime {
    /// Called on the bootstrap thread. The returned CPU owner must be joined on that thread.
    pub(super) fn bootstrap(
        store: ControllerStoreRef<'_>,
        config: &ControllerServerConfig,
    ) -> Result<(Arc<Self>, Option<AdminPasswordWorker>), AdminAccessError> {
        let mode = store.auth_state()?.mode;
        let settings = AdminAuthSettings::new(1)?;
        let policy = if mode != AdminAuthMode::LegacyBootstrap {
            Some(CookiePolicy::parse(config.external_url.as_deref())?)
        } else {
            None
        };
        let worker = if policy.is_some() {
            Some(AdminPasswordWorker::spawn(settings)?)
        } else {
            None
        };
        let runtime = Self::with_client(
            settings,
            policy,
            worker.as_ref().map(AdminPasswordWorker::client),
        );
        Ok((Arc::new(runtime), worker))
    }

    pub(super) fn with_client(
        settings: AdminAuthSettings,
        policy: Option<CookiePolicy>,
        client: Option<AdminPasswordClient>,
    ) -> Self {
        Self {
            settings,
            policy,
            client,
            admission: Arc::new(tokio::sync::Semaphore::new(
                settings.worker_count() + settings.pending_capacity(),
            )),
            failures: Arc::new(Mutex::new(FailureLimiter::default())),
        }
    }
}

pub(super) fn failure(error: AdminAccessError, quota: &'static str) -> HttpFailure {
    match error {
        AdminAccessError::InvalidRequest => (400, "invalid_request"),
        AdminAccessError::Unauthorized => (401, "unauthorized"),
        AdminAccessError::Forbidden => (403, "forbidden"),
        AdminAccessError::NotFound => (404, "not_found"),
        AdminAccessError::Limit => (429, quota),
        AdminAccessError::Busy => (429, "authentication_busy"),
        AdminAccessError::Conflict => (409, "state_conflict"),
        AdminAccessError::LastOwner => (409, "last_owner"),
        AdminAccessError::UserExists => (409, "user_exists"),
        AdminAccessError::Unavailable | AdminAccessError::OperationExpired => {
            (503, "authentication_unavailable")
        }
    }
}

pub(super) fn error_response(error: HttpFailure) -> String {
    no_store(response(
        error.0,
        "application/json",
        &format!("{{\"error\":\"{}\"}}\n", error.1),
    ))
}

fn expired_cookie(request: &str, metadata: &ControllerRuntimeMetadata) -> Option<String> {
    let policy = CookiePolicy::parse(metadata.external_url.as_deref()).ok()?;
    let headers = RequestHeaders::parse(request).ok()?;
    let credential = headers.credential(&policy).ok()??;
    (credential.kind == AdminCredentialKind::WebSession).then(|| policy.cookie("", 0))
}

fn reject_with_cookie(error: HttpFailure, cookie: Option<String>) -> String {
    let response = error_response(error);
    if error.0 == 401
        && let Some(cookie) = cookie
    {
        response.replacen("\r\n\r\n", &format!("\r\nSet-Cookie: {cookie}\r\n\r\n"), 1)
    } else {
        response
    }
}

pub(super) fn rejection_response(
    error: HttpFailure,
    request: &str,
    metadata: &ControllerRuntimeMetadata,
) -> String {
    reject_with_cookie(error, expired_cookie(request, metadata))
}

fn cookie_response(status: u16, body: serde_json::Value, cookie: Option<String>) -> String {
    let body = if status == 204 {
        String::new()
    } else {
        format!("{body}\n")
    };
    let result = no_store(response(status, "application/json", &body));
    match cookie {
        Some(cookie) => {
            result.replacen("\r\n\r\n", &format!("\r\nSet-Cookie: {cookie}\r\n\r\n"), 1)
        }
        None => result,
    }
}

fn user_json(user: &AdminAccountSummary) -> serde_json::Value {
    serde_json::json!({ "id":user.id.as_str(), "username":user.username.as_str(),
        "display_name":user.display_name.as_str(), "role":match user.role { AdminRole::Owner=>"owner", AdminRole::Admin=>"admin", AdminRole::Operator=>"operator",AdminRole::Viewer=>"viewer" },
        "status":match user.status { AdminAccountStatus::Active=>"active",AdminAccountStatus::PendingSetup=>"pending_setup",AdminAccountStatus::Disabled=>"disabled" },
        "record_revision":user.record_revision.value() })
}

fn require_json(headers: &RequestHeaders<'_>) -> Result<(), HttpFailure> {
    if headers.unique("content-type")?.is_none_or(|value| {
        !value
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
    }) {
        return Err((415, "json_required"));
    }
    Ok(())
}

// Missing optional fields mean no input; explicitly null fields are malformed values.
fn present_value<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Shares login's bounded CPU admission and failure budget using the verified actor's
/// canonical username. The caller retains the request owner across this await.
async fn password_action<T: Send + 'static>(
    runtime: &AdminHttpRuntime,
    operation: &AdminAuthOperation,
    username: &str,
    quota: &'static str,
    work: impl FnOnce(&AdminAuthOperation, &AdminPasswordClient) -> Result<T, AdminAccessError>
    + Send
    + 'static,
) -> Result<T, HttpFailure> {
    operation
        .checked_now()
        .map_err(|error| failure(error, quota))?;
    let attempt = FailureLimiter::reserve(&runtime.failures, username)?;
    let client = runtime
        .client
        .as_ref()
        .ok_or((503, "authentication_unavailable"))?
        .clone();
    let permit = runtime
        .admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| (429, "authentication_busy"))?;
    let operation = operation.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work(&operation, &client)
    })
    .await
    .map_err(|_| (503, "authentication_unavailable"))?;
    if matches!(result, Err(AdminAccessError::Unauthorized)) {
        attempt.failed();
    }
    result.map_err(|error| failure(error, quota))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBody {
    username: String,
    password: String,
}
impl Drop for LoginBody {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupBody {
    code: String,
    new_password: String,
}
impl Drop for SetupBody {
    fn drop(&mut self) {
        self.code.zeroize();
        self.new_password.zeroize();
    }
}

pub(super) fn is_route(path: &str) -> bool {
    path == "/api/auth" || path.starts_with("/api/auth/") || accounts::is_route(path)
}

pub(super) async fn handle(request: Zeroizing<String>, state: &ControllerAppState) -> String {
    let cookie = expired_cookie(&request, &state.metadata);
    match handle_inner(request, state).await {
        Ok(result) => result,
        Err(error) => reject_with_cookie(error, cookie),
    }
}

async fn handle_inner(
    request: Zeroizing<String>,
    state: &ControllerAppState,
) -> Result<String, HttpFailure> {
    let mut line = request.lines().next().unwrap_or("").split_whitespace();
    let method = line.next().unwrap_or("");
    let target = line.next().unwrap_or("");
    let path = target.split('?').next().unwrap_or("");
    if target.contains('?')
        && !(method == "GET" && (accounts::is_route(path) || path == "/api/auth/tokens"))
    {
        return Err((400, "invalid_request"));
    }
    let runtime = state
        .admin_auth
        .as_ref()
        .ok_or((503, "authentication_unavailable"))?;
    let mut repository = SharedIdentityRepository(state.store.clone());
    let mode = repository
        .auth_state()
        .map_err(|error| failure(error, "session_limit"))?
        .mode;
    if (method, path) == ("GET", "/api/auth/status") {
        let mode = match mode {
            AdminAuthMode::LegacyBootstrap => "legacy",
            AdminAuthMode::Personal => "personal",
            AdminAuthMode::LocalSetupRequired => "local_setup_required",
        };
        return Ok(cookie_response(
            200,
            serde_json::json!({"mode":mode,"local_setup_required":mode=="local_setup_required"}),
            None,
        ));
    }
    let policy = runtime.policy.as_ref().ok_or((401, "unauthorized"))?;
    let headers = RequestHeaders::parse(&request)?;
    let owner =
        AdminAuthRequest::new(runtime.settings).map_err(|error| failure(error, "session_limit"))?;
    let operation = owner.operation();
    if accounts::is_route(path) || credentials::is_route(path) {
        let (actor, credential) = resolve_actor(&repository, &operation, &headers, policy)?;
        if credential.kind == AdminCredentialKind::WebSession
            && !matches!(method, "GET" | "HEAD" | "OPTIONS")
        {
            require_cookie_mutation(&headers, policy, &credential)?;
        }
        return if accounts::is_route(path) {
            accounts::handle(&request, repository, actor, &operation, runtime, policy).await
        } else {
            credentials::handle(&request, repository, actor, &operation, runtime, policy).await
        };
    }
    match (method, path) {
        ("POST", "/api/auth/login" | "/api/auth/setup") => {
            policy.require_origin(&headers)?;
            require_json(&headers)?;
            // Validate even when replacing an existing session; ambiguous input never selects an actor.
            headers.credential(policy)?;
            let body = request
                .split_once("\r\n\r\n")
                .map(|(_, body)| body)
                .unwrap_or("");
            if body.len() > BODY_LIMIT {
                return Err((413, "request_too_large"));
            }
            let client = runtime
                .client
                .as_ref()
                .ok_or((503, "authentication_unavailable"))?
                .clone();
            let permit = runtime
                .admission
                .clone()
                .try_acquire_owned()
                .map_err(|_| (429, "authentication_busy"))?;
            if path == "/api/auth/login" {
                let body: LoginBody =
                    serde_json::from_str(body).map_err(|_| (400, "invalid_request"))?;
                let attempt = FailureLimiter::reserve(&runtime.failures, &body.username)?;
                let result = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    LoginAdmin::execute(
                        &mut repository,
                        &operation,
                        &client.passwords(&operation),
                        &AdminTokenCrypto::system(),
                        LoginAdminInput {
                            username: &body.username,
                            password: &body.password,
                        },
                    )
                })
                .await
                .map_err(|_| (503, "authentication_unavailable"))?;
                if matches!(result, Err(AdminAccessError::Unauthorized)) {
                    attempt.failed();
                }
                let login = result.map_err(|error| failure(error, "session_limit"))?;
                let secret = login.session.secret.expose_for_delivery();
                Ok(cookie_response(
                    200,
                    serde_json::json!({"user":user_json(&login.account),"expires_at":login.session.expires_at,"csrf_token":csrf(secret)?}),
                    Some(policy.cookie(secret, 28800)),
                ))
            } else {
                let body: SetupBody =
                    serde_json::from_str(body).map_err(|_| (400, "invalid_request"))?;
                let kind = AdminTokenCrypto::identify_purpose(&body.code)
                    .map_err(|error| failure(error, "session_limit"))?;
                if !kind.is_grant() {
                    return Err((401, "unauthorized"));
                }
                let digest = AdminTokenCrypto::system()
                    .digest(kind, &body.code)
                    .map_err(|error| failure(error, "session_limit"))?;
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    CompleteAdminSetup::execute(
                        &mut repository,
                        &operation,
                        &client.passwords(&operation),
                        CompleteAdminSetupInput {
                            kind,
                            digest,
                            new_password: &body.new_password,
                        },
                    )
                })
                .await
                .map_err(|_| (503, "authentication_unavailable"))?
                .map_err(|error| failure(error, "session_limit"))?;
                Ok(cookie_response(204, serde_json::Value::Null, None))
            }
        }
        ("GET", "/api/auth/session") | ("POST", "/api/auth/logout") => {
            let (actor, credential) = resolve_actor(&repository, &operation, &headers, policy)?;
            if method == "POST" {
                require_cookie_mutation(&headers, policy, &credential)?;
                let body = request
                    .split_once("\r\n\r\n")
                    .map(|(_, body)| body)
                    .unwrap_or("");
                if !body.is_empty() {
                    let fields: HashMap<String, serde_json::Value> =
                        serde_json::from_str(body).map_err(|_| (400, "invalid_request"))?;
                    if !fields.is_empty() {
                        return Err((400, "invalid_request"));
                    }
                }
                LogoutAdminSession::execute(&mut repository, &actor, &operation)
                    .map_err(|error| failure(error, "session_limit"))?;
                Ok(cookie_response(
                    204,
                    serde_json::Value::Null,
                    Some(policy.cookie("", 0)),
                ))
            } else {
                let account = repository
                    .account_by_id(actor.user_id())
                    .map_err(|error| failure(error, "session_limit"))?
                    .ok_or((401, "unauthorized"))?;
                let stored = repository
                    .credential_by_id(actor.credential_id())
                    .map_err(|error| failure(error, "session_limit"))?
                    .ok_or((401, "unauthorized"))?;
                Ok(cookie_response(
                    200,
                    serde_json::json!({"user":user_json(&AdminAccountSummary::from(&account)),"expires_at":stored.snapshot().expires_at,
                    "csrf_token":if credential.kind==AdminCredentialKind::WebSession {Some(csrf(credential.raw)?)} else {None}}),
                    None,
                ))
            }
        }
        _ => Err((404, "not_found")),
    }
}

fn resolve_actor<'a, R: AdminIdentityRead + ?Sized>(
    repository: &R,
    operation: &dyn AdminOperation,
    headers: &RequestHeaders<'a>,
    policy: &CookiePolicy,
) -> Result<(AuthenticatedAdmin, HumanCredential<'a>), HttpFailure> {
    let credential = headers.credential(policy)?.ok_or((401, "unauthorized"))?;
    let digest = AdminTokenCrypto::system()
        .digest(credential.kind, credential.raw)
        .map_err(|error| failure(error, "session_limit"))?;
    let actor =
        AuthenticateAdminCredential::execute(repository, operation, credential.kind, &digest)
            .map_err(|error| failure(error, "session_limit"))?;
    Ok((actor, credential))
}

fn require_cookie_mutation(
    headers: &RequestHeaders<'_>,
    policy: &CookiePolicy,
    credential: &HumanCredential<'_>,
) -> Result<(), HttpFailure> {
    if credential.kind != AdminCredentialKind::WebSession {
        return Err((403, "forbidden"));
    }
    policy.require_origin(headers)?;
    let expected = csrf(credential.raw)?;
    let actual = headers
        .unique("x-fleet-csrf")?
        .ok_or((403, "forbidden_csrf"))?;
    if !bool::from(expected.as_bytes().ct_eq(actual.as_bytes())) {
        return Err((403, "forbidden_csrf"));
    }
    Ok(())
}

/// Resolves current human credentials for the existing API adapters, without a legacy fallback.
pub(super) fn authenticate(
    request: &str,
    store: ControllerStoreRef<'_>,
    metadata: &ControllerRuntimeMetadata,
) -> Result<Option<AdminRequestContext>, AdminAccessError> {
    let policy = CookiePolicy::parse(metadata.external_url.as_deref())?;
    let headers = RequestHeaders::parse(request).map_err(|_| AdminAccessError::Unauthorized)?;
    let Some(credential) = headers
        .credential(&policy)
        .map_err(|_| AdminAccessError::Unauthorized)?
    else {
        return Ok(None);
    };
    let digest = AdminTokenCrypto::system().digest(credential.kind, credential.raw)?;
    let owner = AdminAuthRequest::new(AdminAuthSettings::new(1)?)?;
    let actor =
        AuthenticateAdminCredential::execute(&store, &owner.operation(), credential.kind, &digest)?;
    let method = request.split_whitespace().next().unwrap_or("");
    if credential.kind == AdminCredentialKind::WebSession
        && !matches!(method, "GET" | "HEAD" | "OPTIONS")
    {
        require_cookie_mutation(&headers, &policy, &credential)
            .map_err(|_| AdminAccessError::Forbidden)?;
    }
    let account = store
        .account_by_id(actor.user_id())?
        .ok_or(AdminAccessError::Unauthorized)?
        .snapshot();
    Ok(Some(AdminRequestContext {
        actor_id: account.id.as_str().to_owned(),
        role: account.role,
        principal: AdminMutationPrincipal::personal(actor),
    }))
}

/// Keeps authentication/CSRF failures precise before legacy business adapters map their errors.
pub(super) fn preflight(request: &str, state: &ControllerAppState) -> Result<(), HttpFailure> {
    let path = request
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");
    if !path.starts_with("/api/")
        || matches!(
            path,
            "/api/agents/enroll" | "/api/agents/ws" | "/api/controller/identity"
        )
    {
        return Ok(());
    }
    // Ambiguity is rejected in both modes, before any actor or store lookup is selected.
    RequestHeaders::parse(request)?.raw_credential()?;
    let store = state
        .store
        .lock()
        .map_err(|_| (503, "authentication_unavailable"))?;
    let store = ControllerStoreRef::from(&*store);
    if store
        .auth_state()
        .map_err(|error| failure(error, "session_limit"))?
        .mode
        != AdminAuthMode::LegacyBootstrap
    {
        let policy = CookiePolicy::parse(state.metadata.external_url.as_deref())
            .map_err(|error| failure(error, "session_limit"))?;
        RequestHeaders::parse(request)?.credential(&policy)?;
        authenticate(request, store, &state.metadata)
            .map_err(|error| failure(error, "session_limit"))?
            .ok_or((401, "unauthorized"))?;
    }
    Ok(())
}
