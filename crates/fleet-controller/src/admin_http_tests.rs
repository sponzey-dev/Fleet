//! Owned loopback HTTP acceptance of human authentication, separate from Agent credentials.

use super::*;
use crate::admin_crypto::{AdminAuthSettings, AdminTokenCrypto};
use crate::admin_password_worker::{AdminAuthRequest, AdminPasswordWorker};
use fleet_application::admin_identity::{
    AdminAccessError, AdminIdentityRead, AdminIdentityRepository, AdminLocalAuthority,
    InitializeAdminOwner, InitializeOwnerInput,
};
use fleet_domain::{AdminDisplayName, AdminUsername};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};

#[path = "admin_account_http_tests.rs"]
mod account_mutations;

#[path = "admin_self_http_tests.rs"]
mod self_credentials;

#[path = "admin_business_http_tests.rs"]
mod business_writes;

const PASSWORD: &str = "fixture HTTP identity passphrase 47!";
const EXPIRED_LOOKUP: &str = "crd_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const FUTURE_LOOKUP: &str = "crd_ffffffffffffffffffffffffffffffff";

#[test]
fn owner_http_creates_pending_account_and_setup_claims_the_once_returned_code() {
    let server = Server::personal();
    let (cookie, owner) = server.login();
    let created=server.client.post(format!("{}/api/admin/users",server.origin))
        .header("Cookie",&cookie).header("Origin",&server.origin)
        .header("X-Fleet-CSRF",owner["csrf_token"].as_str().unwrap())
        .json(&serde_json::json!({"username":"api_created","display_name":"API fixture person","role":"viewer","current_password":PASSWORD}))
        .send().unwrap();
    assert_eq!(
        created.status(),
        201,
        "owner create must reach the actual mutation endpoint"
    );
    assert_eq!(created.headers()["cache-control"], "no-store");
    let created: serde_json::Value = created.json().unwrap();
    assert_eq!(created["user"]["username"], "api_created");
    assert_eq!(created["user"]["status"], "pending_setup");
    let code = created["setup"]["code"].as_str().unwrap();
    assert!(code.starts_with("fsetup_") && code.len() == 71);
    assert!(created["setup"]["id"].as_str().unwrap().starts_with("crd_"));
    let user_id = created["user"]["id"].as_str().unwrap();
    let detail = server
        .client
        .get(format!("{}/api/admin/users/{user_id}", server.origin))
        .header("Cookie", &cookie)
        .send()
        .unwrap();
    assert_eq!(detail.status(), 200);
    let detail: serde_json::Value = detail.json().unwrap();
    assert!(detail.get("setup").is_none());
    assert_eq!(detail["user"], created["user"]);
    let password = "API newly created fixture passphrase 64!";
    let setup = server
        .client
        .post(format!("{}/api/auth/setup", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"code":code,"new_password":password}))
        .send()
        .unwrap();
    assert_eq!(setup.status(), 204);
    assert!(!setup.headers().contains_key("set-cookie"));
    let login = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"api_created","password":password}))
        .send()
        .unwrap();
    assert_eq!(login.status(), 200);
    let profile: serde_json::Value = login.json().unwrap();
    assert_eq!(profile["user"]["id"], user_id);
    assert_eq!(profile["user"]["role"], "viewer");
}

#[test]
fn owner_http_can_read_account_collection_and_detail_without_credential_material() {
    let server = Server::personal();
    let (cookie, session) = server.login();
    let response = server
        .client
        .get(format!("{}/api/admin/users", server.origin))
        .header("Cookie", &cookie)
        .send()
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "current owner must reach the actual account metadata endpoint"
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    let page: serde_json::Value = response.json().unwrap();
    let users = page["items"].as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert!(page["next_cursor"].is_null());
    assert_eq!(users[0]["id"], session["user"]["id"]);
    let fields = users[0].as_object().unwrap();
    assert_eq!(fields.len(), 6);
    assert!(fields.keys().all(|field| {
        [
            "id",
            "username",
            "display_name",
            "role",
            "status",
            "record_revision",
        ]
        .contains(&field.as_str())
    }));
    let user_id = session["user"]["id"].as_str().unwrap();
    let detail = server
        .client
        .get(format!("{}/api/admin/users/{user_id}", server.origin))
        .header("Cookie", cookie)
        .send()
        .unwrap();
    assert_eq!(detail.status(), 200);
    assert_eq!(
        detail.json::<serde_json::Value>().unwrap()["user"],
        users[0]
    );
}

#[test]
fn personal_https_issues_host_secure_cookie_and_accepts_only_its_session_csrf() {
    let server = Server::with_tls(true);
    let (cookie, profile) = server.login();
    assert!(cookie.starts_with("__Host-fleet_session=fws_"));
    let response = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"http_owner","password":PASSWORD}))
        .send()
        .unwrap();
    assert_eq!(response.status(), 200);
    let flags = response.headers()["set-cookie"].to_str().unwrap();
    for required in [
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=28800",
    ] {
        assert!(flags.contains(required));
    }
    assert!(!flags.contains("Domain="));
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", &cookie)
            .send()
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        server
            .client
            .post(format!("{}/api/auth/logout", server.origin))
            .header("Cookie", &cookie)
            .header("Origin", "http://127.0.0.1")
            .header("X-Fleet-CSRF", profile["csrf_token"].as_str().unwrap())
            .send()
            .unwrap()
            .status(),
        403
    );
    let result = server
        .client
        .post(format!("{}/api/auth/logout", server.origin))
        .header("Cookie", &cookie)
        .header("Origin", &server.origin)
        .header("X-Fleet-CSRF", profile["csrf_token"].as_str().unwrap())
        .send()
        .unwrap();
    assert_eq!(result.status(), 204);
    let cleared = result.headers()["set-cookie"].to_str().unwrap();
    assert!(cleared.starts_with("__Host-fleet_session="));
    assert!(cleared.contains("Max-Age=0") && cleared.contains("Secure"));
}

#[test]
fn personal_http_session_quota_and_password_failure_limit_have_distinct_errors() {
    let server = Server::personal();
    for _ in 0..8 {
        server.login();
    }
    let full = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"http_owner","password":PASSWORD}))
        .send()
        .unwrap();
    assert_eq!(full.status(), 429);
    assert!(!full.headers().contains_key("set-cookie"));
    assert_eq!(
        full.json::<serde_json::Value>().unwrap()["error"],
        "session_limit"
    );
    for _ in 0..5 {
        let wrong=server.client.post(format!("{}/api/auth/login",server.origin)).header("Origin",&server.origin)
            .json(&serde_json::json!({"username":"HTTP_OWNER","password":"incorrect fixture passphrase"})).send().unwrap();
        assert_eq!(wrong.status(), 401);
    }
    let limited = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"http_owner","password":PASSWORD}))
        .send()
        .unwrap();
    assert_eq!(limited.status(), 429);
    assert_eq!(
        limited.json::<serde_json::Value>().unwrap()["error"],
        "authentication_busy"
    );
}

#[test]
fn personal_http_audit_failure_returns_safe_unavailable_and_rolls_back_session_effects() {
    let server = Server::personal();
    let (cookie, profile) = server.login();
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    connection.execute_batch("CREATE TRIGGER fixture_identity_audit_fault BEFORE INSERT ON audit_events WHEN NEW.action IN ('admin_session_created','admin_session_logged_out') BEGIN SELECT RAISE(ABORT,'fixture sensitive SQL diagnostic'); END;").unwrap();
    let before: i64 = connection
        .query_row(
            "SELECT count(*) FROM admin_credentials WHERE kind='web_session'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let login = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"http_owner","password":PASSWORD}))
        .send()
        .unwrap();
    assert_eq!(login.status(), 503);
    assert!(!login.headers().contains_key("set-cookie"));
    assert_eq!(
        login.text().unwrap(),
        "{\"error\":\"authentication_unavailable\"}\n"
    );
    let after: i64 = connection
        .query_row(
            "SELECT count(*) FROM admin_credentials WHERE kind='web_session'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(before, after);
    let logout = server
        .client
        .post(format!("{}/api/auth/logout", server.origin))
        .header("Cookie", &cookie)
        .header("Origin", &server.origin)
        .header("X-Fleet-CSRF", profile["csrf_token"].as_str().unwrap())
        .send()
        .unwrap();
    assert_eq!(logout.status(), 503);
    assert!(!logout.headers().contains_key("set-cookie"));
    assert_eq!(
        logout.text().unwrap(),
        "{\"error\":\"authentication_unavailable\"}\n"
    );
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", cookie)
            .send()
            .unwrap()
            .status(),
        200
    );
    connection
        .execute_batch("DROP TRIGGER fixture_identity_audit_fault;")
        .unwrap();
    server.login();
}

struct FixtureAuthority;
impl AdminLocalAuthority for FixtureAuthority {
    fn require_exclusive(&self) -> Result<AuditActor, AdminAccessError> {
        Ok(AuditActor::new("local:http-fixture"))
    }
}

struct Server {
    _root: tempfile::TempDir,
    origin: String,
    client: reqwest::blocking::Client,
    shutdown: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), ControllerError>>>,
}

impl Server {
    fn pending_user(
        &self,
        cookie: &str,
        username: &str,
        role: AdminRole,
    ) -> fleet_application::admin_identity::CreatedAdminAccount {
        use fleet_application::admin_identity::*;
        use fleet_domain::AdminCredentialKind;
        let mut store = SqliteStore::open(self._root.path().join("controller/fleet.db")).unwrap();
        let settings = AdminAuthSettings::new(1).unwrap();
        let worker = AdminPasswordWorker::spawn(settings).unwrap();
        let client = worker.client();
        let owner = AdminAuthRequest::new(settings).unwrap();
        let operation = owner.operation();
        let digest = AdminTokenCrypto::system()
            .digest(
                AdminCredentialKind::WebSession,
                cookie.split('=').nth(1).unwrap(),
            )
            .unwrap();
        let actor = AuthenticateAdminCredential::execute(
            &store,
            &operation,
            AdminCredentialKind::WebSession,
            &digest,
        )
        .unwrap();
        let result = CreateAdminAccount::execute(
            &mut store,
            &actor,
            &operation,
            &client.passwords(&operation),
            &AdminTokenCrypto::system(),
            CreateAdminAccountInput {
                username: AdminUsername::parse(username).unwrap(),
                display_name: AdminDisplayName::parse(username).unwrap(),
                role,
                current_password: PASSWORD,
            },
        )
        .unwrap();
        worker.shutdown().unwrap();
        result
    }

    fn active_user(
        &self,
        owner_cookie: &str,
        username: &str,
        role: AdminRole,
    ) -> (String, serde_json::Value) {
        let pending = self.pending_user(owner_cookie, username, role);
        let password = "Other HTTP fixture passphrase 51!";
        let setup=self.client.post(format!("{}/api/auth/setup",self.origin)).header("Origin",&self.origin)
            .json(&serde_json::json!({"code":pending.setup.secret.expose_for_delivery(),"new_password":password})).send().unwrap();
        assert_eq!(setup.status(), 204);
        let response = self
            .client
            .post(format!("{}/api/auth/login", self.origin))
            .header("Origin", &self.origin)
            .json(&serde_json::json!({"username":username,"password":password}))
            .send()
            .unwrap();
        assert_eq!(response.status(), 200);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        (cookie, response.json().unwrap())
    }
    fn login(&self) -> (String, serde_json::Value) {
        let response = self
            .client
            .post(format!("{}/api/auth/login", self.origin))
            .header("Origin", &self.origin)
            .json(&serde_json::json!({"username":"http_owner","password":PASSWORD}))
            .send()
            .unwrap();
        assert_eq!(response.status(), 200);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        (cookie, response.json().unwrap())
    }
    fn personal() -> Self {
        Self::with_tls(false)
    }

    fn with_tls(tls: bool) -> Self {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        {
            let _lease =
                fleet_core::controller_data::ControllerDataLease::acquire(root.path()).unwrap();
            let controller = root.path().join("controller");
            fs::create_dir(&controller).unwrap();
            let pair = fleet_core::generate_agent_key_pair().unwrap();
            fs::write(
                controller.join("controller_public.key"),
                pair.public_key_hex,
            )
            .unwrap();
            let private_key = controller.join("controller_private.key");
            fs::write(&private_key, pair.private_key_hex).unwrap();
            fs::set_permissions(private_key, fs::Permissions::from_mode(0o600)).unwrap();
            let mut store = SqliteStore::open(controller.join("fleet.db")).unwrap();
            store
                .insert_admin_token_hash(&hash_token("retired HTTP fixture token"))
                .unwrap();
            assert!(
                store
                    .verify_admin_token_hash(&hash_token("retired HTTP fixture token"))
                    .unwrap()
            );
            let settings = AdminAuthSettings::new(1).unwrap();
            let worker = AdminPasswordWorker::spawn(settings).unwrap();
            let client = worker.client();
            let owner = AdminAuthRequest::new(settings).unwrap();
            let operation = owner.operation();
            let initialized = InitializeAdminOwner::execute(
                &mut store,
                &FixtureAuthority,
                &operation,
                &client.passwords(&operation),
                &AdminTokenCrypto::system(),
                InitializeOwnerInput {
                    username: AdminUsername::parse("http_owner").unwrap(),
                    display_name: AdminDisplayName::parse("HTTP fixture owner").unwrap(),
                    new_password: PASSWORD,
                },
            )
            .unwrap();
            // Synthetic recovered lookup rows exercise startup GC, not token authentication.
            let account = store.account_by_id(&initialized.id).unwrap().unwrap();
            let epoch = store.auth_state().unwrap().epoch;
            let future = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 86400;
            for (id, created, byte) in [(EXPIRED_LOOKUP, 1, 0xee), (FUTURE_LOOKUP, future, 0xff)] {
                let row = fleet_domain::AdminCredential::issue(
                    fleet_domain::AdminCredentialId::parse(id).unwrap(),
                    fleet_domain::AdminCredentialKind::WebSession,
                    fleet_domain::AdminCredentialDigest::from_bytes([byte; 32]),
                    fleet_domain::AdminCredentialBinding::for_account(&account, epoch),
                    created,
                )
                .unwrap();
                store
                    .identity_transaction(|transaction| {
                        transaction.insert_credential(&row.snapshot())
                    })
                    .unwrap();
            }
            worker.shutdown().unwrap();
        }
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none());
        let (tls_cert_path, tls_key_path) = if tls {
            let certificate =
                rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
            let pem = certificate.serialize_pem().unwrap();
            client = client
                .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap());
            let cert_path = root.path().join("controller/fixture_tls.pem");
            let key_path = root.path().join("controller/fixture_tls.key");
            fs::write(&cert_path, pem).unwrap();
            fs::write(&key_path, certificate.serialize_private_key_pem()).unwrap();
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
            (Some(cert_path), Some(key_path))
        } else {
            (None, None)
        };
        let origin = format!("{}://127.0.0.1:{port}", if tls { "https" } else { "http" });
        let config = ControllerServerConfig {
            host: "127.0.0.1".to_owned(),
            port,
            external_url: Some(origin.clone()),
            tls_cert_path,
            tls_key_path,
            agent_client_ca_cert_path: None,
            data_dir: root.path().to_path_buf(),
            database: None,
            secret_provider: None,
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let signal = shutdown.clone();
        let thread = std::thread::spawn(move || {
            start_controller_server_until(config, move || signal.load(Ordering::SeqCst))
        });
        let server = Self {
            _root: root,
            origin,
            client: client.build().unwrap(),
            shutdown,
            thread: Some(thread),
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if server
                .client
                .get(format!("{}/healthz", server.origin))
                .send()
                .is_ok_and(|response| response.status() == 200)
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "fixture startup deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        server
    }
}

#[test]
fn owner_http_metadata_pages_are_scoped_bounded_and_do_not_renew_or_clean_credentials() {
    let server = Server::personal();
    let (cookie, profile) = server.login();
    let mut expected = vec![profile["user"]["id"].as_str().unwrap().to_owned()];
    for n in 0..3 {
        expected.push(
            server
                .pending_user(&cookie, &format!("roster_pending_{n}"), AdminRole::Viewer)
                .account
                .id
                .as_str()
                .to_owned(),
        );
    }
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    let credential_state = || {
        connection.prepare("SELECT credential_id,created_at,expires_at,state FROM admin_credentials ORDER BY credential_id").unwrap()
        .query_map([],|row|Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,String>(3)?))).unwrap()
        .collect::<Result<Vec<_>,_>>().unwrap()
    };
    let before = credential_state();
    let mut ids = Vec::new();
    let mut after = None;
    loop {
        let mut request = server
            .client
            .get(format!("{}/api/admin/users", server.origin))
            .header("Cookie", &cookie)
            .query(&[("limit", "1")]);
        if let Some(cursor) = &after {
            request = request.query(&[("after", cursor)]);
        }
        let response = request.send().unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let page: serde_json::Value = response.json().unwrap();
        let items = page["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        ids.push(items[0]["id"].as_str().unwrap().to_owned());
        after = page["next_cursor"].as_str().map(str::to_owned);
        if after.is_none() {
            break;
        }
        assert!(after.as_ref().unwrap().len() <= 512);
        assert!(ids.len() < expected.len());
    }
    expected.sort();
    assert_eq!(ids, expected);
    assert_eq!(credential_state(), before);
    let snapshot = server
        .client
        .get(format!("{}/api/auth/session", server.origin))
        .header("Cookie", cookie)
        .send()
        .unwrap();
    assert_eq!(
        snapshot.json::<serde_json::Value>().unwrap()["expires_at"],
        profile["expires_at"]
    );
}

#[test]
fn owner_http_metadata_rejects_invalid_query_cursor_scope_and_unknown_body() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let server = Server::personal();
    let (cookie, _) = server.login();
    server.pending_user(&cookie, "cursor_pending", AdminRole::Viewer);
    let response = server
        .client
        .get(format!("{}/api/admin/users?limit=1", server.origin))
        .header("Cookie", &cookie)
        .send()
        .unwrap();
    assert_eq!(response.status(), 200);
    let page: serde_json::Value = response.json().unwrap();
    let cursor = page["next_cursor"].as_str().unwrap();
    let original: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(cursor).unwrap()).unwrap();
    for (field, value) in [
        ("v", serde_json::json!(2)),
        ("purpose", serde_json::json!("own_tokens")),
        (
            "owner",
            serde_json::json!("usr_ffffffffffffffffffffffffffffffff"),
        ),
        (
            "after",
            serde_json::json!("crd_ffffffffffffffffffffffffffffffff"),
        ),
        ("actor", serde_json::json!("spoof")),
    ] {
        let mut altered = original.clone();
        altered[field] = value;
        let bad = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&altered).unwrap());
        let result = server
            .client
            .get(format!("{}/api/admin/users", server.origin))
            .header("Cookie", &cookie)
            .query(&[("after", bad)])
            .send()
            .unwrap();
        assert_eq!(result.status(), 400);
        assert_eq!(
            result.json::<serde_json::Value>().unwrap()["error"],
            "invalid_cursor"
        );
    }
    for query in [
        "limit=0",
        "limit=101",
        "limit=-1",
        "limit=+1",
        "limit=",
        "limit=1&limit=2",
        "lim%69t=1&limit=2",
        "after=",
        "after=usr_ffffffffffffffffffffffffffffffff",
        "actor=spoof",
        "limit=%FF",
        "limit=%",
    ] {
        let result = server
            .client
            .get(format!("{}/api/admin/users?{query}", server.origin))
            .header("Cookie", &cookie)
            .send()
            .unwrap();
        assert_eq!(result.status(), 400);
    }
    let body = server
        .client
        .get(format!("{}/api/admin/users", server.origin))
        .header("Cookie", cookie)
        .json(&serde_json::json!({"actor":"spoof"}))
        .send()
        .unwrap();
    assert_eq!(body.status(), 400);
    assert_eq!(
        server
            .client
            .get(format!("{}/api/admin/users", server.origin))
            .send()
            .unwrap()
            .status(),
        401
    );
}

#[test]
fn owner_http_metadata_forbids_admin_operator_and_viewer_with_valid_credentials() {
    let server = Server::personal();
    let (owner_cookie, owner) = server.login();
    assert_eq!(
        server
            .client
            .get(format!("{}/api/admin/users", server.origin))
            .header("Cookie", &owner_cookie)
            .send()
            .unwrap()
            .status(),
        200
    );
    for (name, role) in [
        ("roster_admin", AdminRole::Admin),
        ("roster_operator", AdminRole::Operator),
        ("roster_viewer", AdminRole::Viewer),
    ] {
        let (cookie, profile) = server.active_user(&owner_cookie, name, role);
        assert_eq!(
            server
                .client
                .get(format!("{}/api/agents", server.origin))
                .header("Cookie", &cookie)
                .send()
                .unwrap()
                .status(),
            200
        );
        for path in [
            "/api/admin/users".to_owned(),
            format!("/api/admin/users/{}", owner["user"]["id"].as_str().unwrap()),
            format!(
                "/api/admin/users/{}",
                profile["user"]["id"].as_str().unwrap()
            ),
            "/api/admin/users/usr_ffffffffffffffffffffffffffffffff".to_owned(),
        ] {
            let result = server
                .client
                .get(format!("{}{path}", server.origin))
                .header("Cookie", &cookie)
                .send()
                .unwrap();
            assert_eq!(result.status(), 403);
            assert_eq!(
                result.json::<serde_json::Value>().unwrap()["error"],
                "forbidden"
            );
        }
    }
}

#[test]
fn owner_http_corrupt_metadata_returns_no_partial_page_and_safe_unavailable() {
    let server = Server::personal();
    let (cookie, _) = server.login();
    let other = server.pending_user(&cookie, "corrupt_pending", AdminRole::Viewer);
    assert_eq!(
        server
            .client
            .get(format!("{}/api/admin/users", server.origin))
            .header("Cookie", &cookie)
            .send()
            .unwrap()
            .status(),
        200
    );
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    connection
        .execute(
            "UPDATE admin_accounts SET display_name=char(1) WHERE user_id=?1",
            [other.account.id.as_str()],
        )
        .unwrap();
    for path in [
        "/api/admin/users?limit=1".to_owned(),
        format!("/api/admin/users/{}", other.account.id.as_str()),
    ] {
        let result = server
            .client
            .get(format!("{}{path}", server.origin))
            .header("Cookie", &cookie)
            .send()
            .unwrap();
        assert_eq!(result.status(), 503);
        assert_eq!(result.headers()["cache-control"], "no-store");
        assert_eq!(
            result.json::<serde_json::Value>().unwrap(),
            serde_json::json!({"error":"authentication_unavailable"})
        );
    }
    assert_eq!(
        server
            .client
            .get(format!("{}/api/auth/session", server.origin))
            .header("Cookie", &cookie)
            .send()
            .unwrap()
            .status(),
        200
    );
    connection
        .execute(
            "UPDATE admin_accounts SET display_name='corrupt_pending' WHERE user_id=?1",
            [other.account.id.as_str()],
        )
        .unwrap();
    assert_eq!(
        server
            .client
            .get(format!("{}/api/admin/users", server.origin))
            .header("Cookie", cookie)
            .send()
            .unwrap()
            .status(),
        200
    );
}

#[test]
fn personal_http_startup_reclaims_expired_lookup_before_any_auth_request_and_preserves_future_rows()
{
    let server = Server::personal();
    let store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    assert!(
        store
            .credential_by_id(&fleet_domain::AdminCredentialId::parse(EXPIRED_LOOKUP).unwrap())
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .credential_by_id(&fleet_domain::AdminCredentialId::parse(FUTURE_LOOKUP).unwrap())
            .unwrap()
            .is_some()
    );
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    let accounts: i64 = connection
        .query_row("SELECT count(*) FROM admin_accounts", [], |row| row.get(0))
        .unwrap();
    let audit: i64 = connection
        .query_row(
            "SELECT count(*) FROM audit_events WHERE action='admin_owner_initialized'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((accounts, audit), (1, 1));
    server.login();
}

#[test]
fn personal_controller_requires_bootstrap_origin_without_changing_identity_or_holding_the_lease() {
    let mut server = Server::personal();
    server.shutdown.store(true, Ordering::SeqCst);
    server.thread.take().unwrap().join().unwrap().unwrap();
    let database = server._root.path().join("controller/fleet.db");
    let before = SqliteStore::open(&database).unwrap();
    let username = AdminUsername::parse("http_owner").unwrap();
    let account = before
        .account_by_username(&username)
        .unwrap()
        .unwrap()
        .snapshot();
    let auth = before.auth_state().unwrap();
    let key_path = server
        ._root
        .path()
        .join("controller/controller_private.key");
    let key = fs::read(&key_path).unwrap();
    drop(before);
    let config = ControllerServerConfig {
        host: "127.0.0.1".to_owned(),
        port: 0,
        external_url: None,
        tls_cert_path: None,
        tls_key_path: None,
        agent_client_ca_cert_path: None,
        data_dir: server._root.path().to_path_buf(),
        database: None,
        secret_provider: None,
    };
    let result = start_controller_server_until(config, || true);
    assert!(
        matches!(result,Err(ControllerError::Json(ref message)) if message=="administrator authentication bootstrap unavailable")
    );
    let _lease =
        fleet_core::controller_data::ControllerDataLease::acquire(server._root.path()).unwrap();
    let after = SqliteStore::open(&database).unwrap();
    assert!(
        after
            .account_by_username(&username)
            .unwrap()
            .unwrap()
            .snapshot()
            == account
    );
    assert_eq!(after.auth_state().unwrap(), auth);
    assert!(fs::read(key_path).unwrap() == key);
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                assert!(matches!(result, Ok(Ok(()))));
            }
        }
    }
}

#[test]
fn personal_http_login_session_protected_read_and_logout_succeed() {
    let server = Server::personal();
    let login = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"http_owner","password":PASSWORD}))
        .send()
        .unwrap();
    assert_eq!(login.status(), 200, "registered account must really log in");
    assert_eq!(login.headers()["cache-control"], "no-store");
    let cookie = login.headers()["set-cookie"].to_str().unwrap().to_owned();
    assert!(cookie.starts_with("fleet_session=fws_"));
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Max-Age=28800"));
    let cookie = cookie.split(';').next().unwrap().to_owned();
    let profile: serde_json::Value = login.json().unwrap();
    assert_eq!(profile["user"]["username"], "http_owner");
    let csrf = profile["csrf_token"].as_str().unwrap();
    assert!(!csrf.is_empty());
    let session = server
        .client
        .get(format!("{}/api/auth/session", server.origin))
        .header("Cookie", &cookie)
        .send()
        .unwrap();
    assert_eq!(session.status(), 200);
    let session: serde_json::Value = session.json().unwrap();
    assert_eq!(session["user"]["id"], profile["user"]["id"]);
    assert!(session["csrf_token"] == csrf);
    assert_eq!(session["expires_at"], profile["expires_at"]);
    let agents = server
        .client
        .get(format!("{}/api/agents", server.origin))
        .header("Cookie", &cookie)
        .send()
        .unwrap();
    assert_eq!(
        agents.status(),
        200,
        "cookie must authenticate an existing protected API"
    );
    assert_eq!(
        agents
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let logout = server
        .client
        .post(format!("{}/api/auth/logout", server.origin))
        .header("Cookie", &cookie)
        .header("Origin", &server.origin)
        .header("X-Fleet-CSRF", csrf)
        .send()
        .unwrap();
    assert_eq!(logout.status(), 204);
    assert!(
        logout.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let replay = server
        .client
        .get(format!("{}/api/agents", server.origin))
        .header("Cookie", &cookie)
        .send()
        .unwrap();
    assert_eq!(replay.status(), 401);
    let stale_logout = server
        .client
        .post(format!("{}/api/auth/logout", server.origin))
        .header("Cookie", &cookie)
        .header("Origin", &server.origin)
        .header("X-Fleet-CSRF", csrf)
        .send()
        .unwrap();
    assert_eq!(stale_logout.status(), 401);
    assert!(
        stale_logout
            .headers()
            .get("set-cookie")
            .is_some_and(|value| value.to_str().unwrap().contains("Max-Age=0"))
    );
}

#[test]
fn personal_http_ambiguous_authentication_never_selects_an_actor() {
    let server = Server::personal();
    let (cookie, _) = server.login();
    for headers in [
        vec![
            ("Cookie", cookie.as_str()),
            ("Authorization", "Bearer invalid"),
        ],
        vec![("Cookie", cookie.as_str()), ("Cookie", cookie.as_str())],
        vec![
            ("Authorization", "Bearer one"),
            ("Authorization", "Bearer two"),
        ],
    ] {
        let mut request = server.client.get(format!("{}/api/agents", server.origin));
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let result = request.send().unwrap();
        assert_eq!(
            result.status(),
            400,
            "ambiguous credential headers must be rejected explicitly"
        );
        assert_eq!(
            result.json::<serde_json::Value>().unwrap()["error"],
            "ambiguous_authentication"
        );
    }
    let result = server
        .client
        .get(format!("{}/api/agents", server.origin))
        .body(format!(
            "Authorization: Bearer {}",
            cookie.split('=').nth(1).unwrap()
        ))
        .send()
        .unwrap();
    assert_eq!(result.status(), 401);
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", cookie)
            .send()
            .unwrap()
            .status(),
        200
    );
}

#[test]
fn personal_http_csrf_is_bound_to_one_session_and_logout_preserves_other_sessions() {
    let server = Server::personal();
    let (first, profile) = server.login();
    let (second, other) = server.login();
    let first_csrf = profile["csrf_token"].as_str().unwrap();
    let second_csrf = other["csrf_token"].as_str().unwrap();
    assert!(first != second && first_csrf != second_csrf);
    for (origin, csrf) in [
        (None, None),
        (Some(server.origin.as_str()), None),
        (Some("https://foreign.invalid"), Some(first_csrf)),
        (Some(server.origin.as_str()), Some(second_csrf)),
    ] {
        let mut request = server
            .client
            .post(format!("{}/api/auth/logout", server.origin))
            .header("Cookie", &first);
        if let Some(origin) = origin {
            request = request.header("Origin", origin);
        }
        if let Some(csrf) = csrf {
            request = request.header("X-Fleet-CSRF", csrf);
        }
        assert_eq!(request.send().unwrap().status(), 403);
    }
    let result = server
        .client
        .post(format!("{}/api/auth/logout", server.origin))
        .header("Cookie", &first)
        .header("Origin", &server.origin)
        .header("X-Fleet-CSRF", first_csrf)
        .send()
        .unwrap();
    assert_eq!(result.status(), 204);
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", first)
            .send()
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", second)
            .send()
            .unwrap()
            .status(),
        200
    );
}

#[test]
fn personal_http_login_requires_origin_json_and_bounded_known_fields() {
    let server = Server::personal();
    let (_, profile) = server.login();
    assert_eq!(profile["user"]["role"], "owner");
    let valid = serde_json::json!({"username":"http_owner","password":PASSWORD});
    let charset = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .header("Content-Type", "application/json; charset=utf-8")
        .body(valid.to_string())
        .send()
        .unwrap();
    assert_eq!(charset.status(), 200);
    for origin in [None, Some("null"), Some("https://foreign.invalid")] {
        let mut request = server
            .client
            .post(format!("{}/api/auth/login", server.origin))
            .json(&valid);
        if let Some(origin) = origin {
            request = request.header("Origin", origin);
        }
        let response = request.send().unwrap();
        assert_eq!(response.status(), 403);
        assert!(!response.headers().contains_key("set-cookie"));
    }
    let wrong_type = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .header("Content-Type", "text/plain")
        .body(valid.to_string())
        .send()
        .unwrap();
    assert_eq!(wrong_type.status(), 415);
    for body in [
        serde_json::json!({"username":"http_owner","password":PASSWORD,"actor":"spoof"})
            .to_string(),
        "{\"username\":\"http_owner\",\"username\":\"other\",\"password\":\"fake\"}".to_owned(),
    ] {
        assert_eq!(
            server
                .client
                .post(format!("{}/api/auth/login", server.origin))
                .header("Origin", &server.origin)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .unwrap()
                .status(),
            400
        );
    }
    for (body, status) in [(vec![0xff], 400), (vec![b' '; 16 * 1024 + 1], 413)] {
        assert_eq!(
            server
                .client
                .post(format!("{}/api/auth/login", server.origin))
                .header("Origin", &server.origin)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .unwrap()
                .status(),
            status
        );
    }
    assert_eq!(
        server
            .client
            .post(format!("{}/api/auth/login?code=fixture", server.origin))
            .header("Origin", &server.origin)
            .json(&valid)
            .send()
            .unwrap()
            .status(),
        400
    );
    let mut errors = Vec::new();
    for (username, password) in [
        ("http_owner", "incorrect fixture password"),
        ("unknown_person", "incorrect fixture password"),
    ] {
        let result = server
            .client
            .post(format!("{}/api/auth/login", server.origin))
            .header("Origin", &server.origin)
            .json(&serde_json::json!({"username":username,"password":password}))
            .send()
            .unwrap();
        assert_eq!(result.status(), 401);
        assert_eq!(result.headers()["cache-control"], "no-store");
        assert!(!result.headers().contains_key("set-cookie"));
        errors.push(result.text().unwrap());
    }
    assert_eq!(errors[0], errors[1]);
}

#[test]
fn personal_http_pat_is_current_user_bound_and_cannot_be_a_web_or_legacy_credential() {
    use fleet_application::admin_identity::*;
    use fleet_domain::AdminCredentialKind;
    let server = Server::personal();
    let (cookie, profile) = server.login();
    let mut store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    let settings = AdminAuthSettings::new(1).unwrap();
    let worker = AdminPasswordWorker::spawn(settings).unwrap();
    let client = worker.client();
    let owner = AdminAuthRequest::new(settings).unwrap();
    let operation = owner.operation();
    let web_secret = cookie.split('=').nth(1).unwrap();
    let digest = AdminTokenCrypto::system()
        .digest(AdminCredentialKind::WebSession, web_secret)
        .unwrap();
    let actor = AuthenticateAdminCredential::execute(
        &store,
        &operation,
        AdminCredentialKind::WebSession,
        &digest,
    )
    .unwrap();
    let issued = CreateAdminPersonalToken::execute(
        &mut store,
        &actor,
        &operation,
        &client.passwords(&operation),
        &AdminTokenCrypto::system(),
        CreateAdminPersonalTokenInput {
            current_password: PASSWORD,
            label: None,
        },
    )
    .unwrap();
    worker.shutdown().unwrap();
    let token = issued.secret.expose_for_delivery();
    let agents = server
        .client
        .get(format!("{}/api/agents", server.origin))
        .bearer_auth(token)
        .send()
        .unwrap();
    assert_eq!(agents.status(), 200);
    let session = server
        .client
        .get(format!("{}/api/auth/session", server.origin))
        .bearer_auth(token)
        .send()
        .unwrap();
    assert_eq!(session.status(), 200);
    let session: serde_json::Value = session.json().unwrap();
    assert_eq!(session["user"]["id"], profile["user"]["id"]);
    assert!(session["csrf_token"].is_null());
    assert_eq!(
        server
            .client
            .post(format!("{}/api/auth/logout", server.origin))
            .bearer_auth(token)
            .header("Origin", &server.origin)
            .send()
            .unwrap()
            .status(),
        403
    );
    for wrong in [web_secret, "retired HTTP fixture token"] {
        assert_eq!(
            server
                .client
                .get(format!("{}/api/agents", server.origin))
                .bearer_auth(wrong)
                .send()
                .unwrap()
                .status(),
            401
        );
    }
    assert_eq!(
        server
            .client
            .get(format!("{}/api/auth/session", server.origin))
            .header("Cookie", format!("fleet_session={token}"))
            .send()
            .unwrap()
            .status(),
        401
    );
    RevokeOwnAdminPersonalToken::execute(&mut store, &actor, &operation, &issued.id).unwrap();
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .bearer_auth(token)
            .send()
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", cookie)
            .send()
            .unwrap()
            .status(),
        200
    );
    let status = server
        .client
        .get(format!("{}/api/auth/status", server.origin))
        .send()
        .unwrap();
    assert_eq!(status.status(), 200);
    assert_eq!(
        status.json::<serde_json::Value>().unwrap(),
        serde_json::json!({"mode":"personal","local_setup_required":false})
    );
}

#[test]
fn personal_http_setup_consumes_a_real_grant_without_logging_in() {
    use fleet_application::admin_identity::*;
    use fleet_domain::AdminCredentialKind;
    let server = Server::personal();
    let (cookie, _) = server.login();
    let mut store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    let settings = AdminAuthSettings::new(1).unwrap();
    let worker = AdminPasswordWorker::spawn(settings).unwrap();
    let client = worker.client();
    let owner = AdminAuthRequest::new(settings).unwrap();
    let operation = owner.operation();
    let digest = AdminTokenCrypto::system()
        .digest(
            AdminCredentialKind::WebSession,
            cookie.split('=').nth(1).unwrap(),
        )
        .unwrap();
    let actor = AuthenticateAdminCredential::execute(
        &store,
        &operation,
        AdminCredentialKind::WebSession,
        &digest,
    )
    .unwrap();
    let created = CreateAdminAccount::execute(
        &mut store,
        &actor,
        &operation,
        &client.passwords(&operation),
        &AdminTokenCrypto::system(),
        CreateAdminAccountInput {
            username: AdminUsername::parse("http_other").unwrap(),
            display_name: AdminDisplayName::parse("Other fixture person").unwrap(),
            role: AdminRole::Viewer,
            current_password: PASSWORD,
        },
    )
    .unwrap();
    worker.shutdown().unwrap();
    let new_password = "Second fixture person passphrase 82!";
    let body = serde_json::json!({"code":created.setup.secret.expose_for_delivery(),"new_password":new_password});
    for origin in [None, Some("null"), Some("https://foreign.invalid")] {
        let mut rejected = server
            .client
            .post(format!("{}/api/auth/setup", server.origin))
            .json(&body);
        if let Some(origin) = origin {
            rejected = rejected.header("Origin", origin);
        }
        let rejected = rejected.send().unwrap();
        assert_eq!(rejected.status(), 403);
        assert!(!rejected.headers().contains_key("set-cookie"));
    }
    let setup = server
        .client
        .post(format!("{}/api/auth/setup", server.origin))
        .header("Origin", &server.origin)
        .json(&body)
        .send()
        .unwrap();
    assert_eq!(setup.status(), 204);
    assert!(!setup.headers().contains_key("set-cookie"));
    assert_eq!(
        server
            .client
            .post(format!("{}/api/auth/setup", server.origin))
            .header("Origin", &server.origin)
            .json(&body)
            .send()
            .unwrap()
            .status(),
        401
    );
    let login = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"http_other","password":new_password}))
        .send()
        .unwrap();
    assert_eq!(login.status(), 200);
    let viewer_cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let user: serde_json::Value = login.json().unwrap();
    assert_eq!(user["user"]["role"], "viewer");
    assert_eq!(user["user"]["id"], created.account.id.as_str());
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", &viewer_cookie)
            .send()
            .unwrap()
            .status(),
        200
    );
    let forbidden = server
        .client
        .post(format!("{}/api/agents/missing/revoke-key", server.origin))
        .header("Cookie", &viewer_cookie)
        .header("Origin", &server.origin)
        .header("X-Fleet-CSRF", user["csrf_token"].as_str().unwrap())
        .json(&serde_json::json!({}))
        .send()
        .unwrap();
    assert_eq!(forbidden.status(), 403);
    assert_eq!(
        forbidden.json::<serde_json::Value>().unwrap()["required_permission"],
        "agent_revoke"
    );
    let changer = AdminPasswordWorker::spawn(settings).unwrap();
    let client = changer.client();
    ChangeAdminAccount::execute(
        &mut store,
        &actor,
        &operation,
        &client.passwords(&operation),
        ChangeAdminAccountInput {
            user_id: created.account.id.clone(),
            display_name: None,
            role: Some(AdminRole::Operator),
            disable: false,
            current_password: PASSWORD,
        },
    )
    .unwrap();
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", viewer_cookie)
            .send()
            .unwrap()
            .status(),
        401
    );
    let login = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"http_other","password":new_password}))
        .send()
        .unwrap();
    assert_eq!(login.status(), 200);
    let operator_cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        login.json::<serde_json::Value>().unwrap()["user"]["role"],
        "operator"
    );
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", &operator_cookie)
            .send()
            .unwrap()
            .status(),
        200
    );
    ChangeAdminAccount::execute(
        &mut store,
        &actor,
        &operation,
        &client.passwords(&operation),
        ChangeAdminAccountInput {
            user_id: created.account.id,
            display_name: None,
            role: None,
            disable: true,
            current_password: PASSWORD,
        },
    )
    .unwrap();
    changer.shutdown().unwrap();
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", operator_cookie)
            .send()
            .unwrap()
            .status(),
        401
    );
    let disabled = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"http_other","password":new_password}))
        .send()
        .unwrap();
    assert_eq!(disabled.status(), 401);
    assert_eq!(
        disabled.json::<serde_json::Value>().unwrap()["error"],
        "unauthorized"
    );
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", cookie)
            .send()
            .unwrap()
            .status(),
        200
    );
}
