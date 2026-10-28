//! Owner mutation acceptance through owned loopback HTTP and real password workers.

use super::*;
use fleet_application::admin_identity::*;
use fleet_domain::AdminCredentialKind;

const OTHER_PASSWORD: &str = "Other HTTP fixture passphrase 51!";

#[test]
fn owner_https_self_reset_clears_secure_cookie_and_all_own_proofs_but_keeps_other_owner() {
    let server = Server::with_tls(true);
    let (cookie, owner) = server.login();
    let (other_cookie, _) = server.active_user(&cookie, "reset_other_owner", AdminRole::Owner);
    let token = personal_token(&server, &cookie, PASSWORD);
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    connection
        .execute(
            "DELETE FROM admin_credentials WHERE credential_id=?1",
            [FUTURE_LOOKUP],
        )
        .unwrap();
    let response = mutation(
        &server,
        &cookie,
        &owner,
        reqwest::Method::POST,
        &format!(
            "/api/admin/users/{}/password-reset",
            owner["user"]["id"].as_str().unwrap()
        ),
        serde_json::json!({"current_password":PASSWORD}),
    );
    assert_eq!(response.status(), 201);
    let cleared = response.headers()["set-cookie"].to_str().unwrap();
    assert!(cleared.starts_with("__Host-fleet_session="));
    assert!(cleared.contains("Max-Age=0") && cleared.contains("Secure"));
    let body: serde_json::Value = response.json().unwrap();
    assert_eq!(session_status(&server, &cookie), 401);
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .bearer_auth(token.secret.expose_for_delivery())
            .send()
            .unwrap()
            .status(),
        401
    );
    assert_eq!(session_status(&server, &other_cookie), 200);
    let new_password = "Self reset HTTPS fixture passphrase 97!";
    let claim = server
        .client
        .post(format!("{}/api/auth/setup", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"code":body["reset"]["code"],"new_password":new_password}))
        .send()
        .unwrap();
    assert_eq!(claim.status(), 204);
    let login = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"http_owner","password":new_password}))
        .send()
        .unwrap();
    assert_eq!(login.status(), 200);
    assert_eq!(
        login.json::<serde_json::Value>().unwrap()["user"]["role"],
        "owner"
    );
}

#[test]
fn owner_http_mutations_reject_spoofed_null_duplicate_and_unproved_input_and_share_failure_budget()
{
    let server = Server::personal();
    let (cookie, owner) = server.login();
    let path = format!("/api/admin/users/{}", owner["user"]["id"].as_str().unwrap());
    for body in [
        serde_json::json!({"display_name":"Unapplied","role":null,"current_password":PASSWORD}),
        serde_json::json!({"display_name":null,"role":"owner","current_password":PASSWORD}),
        serde_json::json!({"display_name":"Unapplied","disable":null,"current_password":PASSWORD}),
        serde_json::json!({"disable":false,"current_password":PASSWORD}),
        serde_json::json!({"role":"Owner","current_password":PASSWORD}),
        serde_json::json!({"role":"owner","actor":"spoof","current_password":PASSWORD}),
        serde_json::json!({"role":"owner","username":"renamed","current_password":PASSWORD}),
        serde_json::json!({"role":"owner","status":"active","current_password":PASSWORD}),
        serde_json::json!({"role":"owner"}),
    ] {
        assert_eq!(
            mutation(
                &server,
                &cookie,
                &owner,
                reqwest::Method::PATCH,
                &path,
                body
            )
            .status(),
            400
        );
    }
    let duplicate=server.client.patch(format!("{}{path}",server.origin)).header("Cookie",&cookie)
        .header("Origin",&server.origin).header("X-Fleet-CSRF",owner["csrf_token"].as_str().unwrap())
        .header("Content-Type","application/json")
        .body("{\"display_name\":\"unapplied\",\"current_password\":\"one\",\"current_password\":\"two\"}")
        .send().unwrap();
    assert_eq!(duplicate.status(), 400);
    let valid = serde_json::json!({"display_name":"Unapplied","current_password":PASSWORD});
    for (origin, csrf) in [
        (None, None),
        (Some(server.origin.as_str()), None),
        (Some("https://foreign.invalid"), Some("wrong")),
        (Some(server.origin.as_str()), Some("wrong")),
    ] {
        let mut request = server
            .client
            .patch(format!("{}{path}", server.origin))
            .header("Cookie", &cookie)
            .json(&valid);
        if let Some(origin) = origin {
            request = request.header("Origin", origin);
        }
        if let Some(csrf) = csrf {
            request = request.header("X-Fleet-CSRF", csrf);
        }
        assert_eq!(request.send().unwrap().status(), 403);
    }
    let wrong_type = server
        .client
        .patch(format!("{}{path}", server.origin))
        .header("Cookie", &cookie)
        .header("Origin", &server.origin)
        .header("X-Fleet-CSRF", owner["csrf_token"].as_str().unwrap())
        .header("Content-Type", "text/plain")
        .body(valid.to_string())
        .send()
        .unwrap();
    assert_eq!(wrong_type.status(), 415);
    let oversized = mutation(
        &server,
        &cookie,
        &owner,
        reqwest::Method::PATCH,
        &path,
        serde_json::json!({"current_password":PASSWORD,"display_name":"x".repeat(16*1024)}),
    );
    assert_eq!(oversized.status(), 413);
    // Changing the requested target/username cannot acquire a fresh password-guessing budget.
    for n in 0..5 {
        let response = mutation(
            &server,
            &cookie,
            &owner,
            reqwest::Method::POST,
            "/api/admin/users",
            serde_json::json!({"username":format!("guess_{n}"),"display_name":"Unapplied","role":"viewer","current_password":"wrong fixture passphrase"}),
        );
        assert_eq!(response.status(), 401);
    }
    assert_eq!(
        mutation(
            &server,
            &cookie,
            &owner,
            reqwest::Method::PATCH,
            &path,
            valid
        )
        .status(),
        429
    );
    let login = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"HTTP_OWNER","password":PASSWORD}))
        .send()
        .unwrap();
    assert_eq!(login.status(), 429);
    assert_eq!(session_status(&server, &cookie), 200);
    let store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    assert_eq!(
        store
            .account_by_username(&AdminUsername::parse("http_owner").unwrap())
            .unwrap()
            .unwrap()
            .snapshot()
            .display_name
            .as_str(),
        owner["user"]["display_name"].as_str().unwrap()
    );
    assert!(
        store
            .account_by_username(&AdminUsername::parse("guess_0").unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn owner_http_pat_can_manage_accounts_with_same_request_password_without_cookie_csrf() {
    let server = Server::personal();
    let (cookie, _) = server.login();
    let token = personal_token(&server, &cookie, PASSWORD);
    let create = |password| {
        server.client.post(format!("{}/api/admin/users",server.origin))
        .bearer_auth(token.secret.expose_for_delivery()).json(&serde_json::json!({"username":"pat_created","display_name":"PAT managed","role":"viewer","current_password":password})).send().unwrap()
    };
    assert_eq!(create("wrong fixture passphrase").status(), 401);
    let response = create(PASSWORD);
    assert_eq!(response.status(), 201);
    assert!(!response.headers().contains_key("set-cookie"));
    let created: serde_json::Value = response.json().unwrap();
    assert_eq!(created["user"]["status"], "pending_setup");
    let duplicate = create(PASSWORD);
    assert_eq!(duplicate.status(), 409);
    assert_eq!(
        duplicate.json::<serde_json::Value>().unwrap()["error"],
        "user_exists"
    );
    assert_eq!(session_status(&server, &cookie), 200);
}

pub(super) fn mutation(
    server: &Server,
    cookie: &str,
    profile: &serde_json::Value,
    method: reqwest::Method,
    path: &str,
    body: serde_json::Value,
) -> reqwest::blocking::Response {
    server
        .client
        .request(method, format!("{}{path}", server.origin))
        .header("Cookie", cookie)
        .header("Origin", &server.origin)
        .header("X-Fleet-CSRF", profile["csrf_token"].as_str().unwrap())
        .json(&body)
        .send()
        .unwrap()
}

pub(super) fn session_status(server: &Server, cookie: &str) -> u16 {
    server
        .client
        .get(format!("{}/api/auth/session", server.origin))
        .header("Cookie", cookie)
        .send()
        .unwrap()
        .status()
        .as_u16()
}

pub(super) fn personal_token(
    server: &Server,
    cookie: &str,
    password: &str,
) -> IssuedAdminCredential {
    let mut store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    let settings = AdminAuthSettings::new(1).unwrap();
    let worker = AdminPasswordWorker::spawn(settings).unwrap();
    let request = AdminAuthRequest::new(settings).unwrap();
    let operation = request.operation();
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
    let issued = CreateAdminPersonalToken::execute(
        &mut store,
        &actor,
        &operation,
        &worker.client().passwords(&operation),
        &AdminTokenCrypto::system(),
        CreateAdminPersonalTokenInput {
            current_password: password,
            label: None,
        },
    )
    .unwrap();
    worker.shutdown().unwrap();
    issued
}

#[test]
fn owner_http_metadata_change_keeps_credentials_but_role_and_disable_revoke_them() {
    let server = Server::personal();
    let (owner_cookie, owner) = server.login();
    let (cookie, person) = server.active_user(&owner_cookie, "managed_person", AdminRole::Operator);
    let id = person["user"]["id"].as_str().unwrap();
    let path = format!("/api/admin/users/{id}");
    let token = personal_token(&server, &cookie, OTHER_PASSWORD);
    let renamed = mutation(
        &server,
        &owner_cookie,
        &owner,
        reqwest::Method::PATCH,
        &path,
        serde_json::json!({"display_name":"Human readable name","role":"operator","current_password":PASSWORD}),
    );
    assert_eq!(renamed.status(), 200);
    assert!(!renamed.headers().contains_key("set-cookie"));
    assert_eq!(
        renamed.json::<serde_json::Value>().unwrap()["user"]["display_name"],
        "Human readable name"
    );
    assert_eq!(session_status(&server, &cookie), 200);
    let pat_status = || {
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .bearer_auth(token.secret.expose_for_delivery())
            .send()
            .unwrap()
            .status()
            .as_u16()
    };
    assert_eq!(pat_status(), 200);
    let changed = mutation(
        &server,
        &owner_cookie,
        &owner,
        reqwest::Method::PATCH,
        &path,
        serde_json::json!({"role":"viewer","current_password":PASSWORD}),
    );
    assert_eq!(changed.status(), 200);
    assert!(!changed.headers().contains_key("set-cookie"));
    assert_eq!(session_status(&server, &cookie), 401);
    assert_eq!(pat_status(), 401);
    assert_eq!(session_status(&server, &owner_cookie), 200);
    let login = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"managed_person","password":OTHER_PASSWORD}))
        .send()
        .unwrap();
    assert_eq!(login.status(), 200);
    let cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        login.json::<serde_json::Value>().unwrap()["user"]["role"],
        "viewer"
    );
    let disabled = mutation(
        &server,
        &owner_cookie,
        &owner,
        reqwest::Method::PATCH,
        &path,
        serde_json::json!({"disable":true,"current_password":PASSWORD}),
    );
    assert_eq!(disabled.status(), 200);
    assert_eq!(
        disabled.json::<serde_json::Value>().unwrap()["user"]["status"],
        "disabled"
    );
    assert_eq!(session_status(&server, &cookie), 401);
    let login = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"managed_person","password":OTHER_PASSWORD}))
        .send()
        .unwrap();
    assert_eq!(login.status(), 401);
    assert_eq!(session_status(&server, &owner_cookie), 200);
}

#[test]
fn owner_http_reset_replaces_pending_grants_and_restores_disabled_person_only_after_claim() {
    let server = Server::personal();
    let (owner_cookie, owner) = server.login();
    let pending = server.pending_user(&owner_cookie, "pending_reset", AdminRole::Viewer);
    let reset_path = format!(
        "/api/admin/users/{}/password-reset",
        pending.account.id.as_str()
    );
    let reset = mutation(
        &server,
        &owner_cookie,
        &owner,
        reqwest::Method::POST,
        &reset_path,
        serde_json::json!({"current_password":PASSWORD}),
    );
    assert_eq!(reset.status(), 201);
    assert!(!reset.headers().contains_key("set-cookie"));
    let reset: serde_json::Value = reset.json().unwrap();
    let code = reset["reset"]["code"].as_str().unwrap();
    assert!(code.starts_with("freset_") && code.len() == 71);
    for old in [pending.setup.secret.expose_for_delivery(), code] {
        let response = server
            .client
            .post(format!("{}/api/auth/setup", server.origin))
            .header("Origin", &server.origin)
            .json(&serde_json::json!({"code":old,"new_password":OTHER_PASSWORD}))
            .send()
            .unwrap();
        assert_eq!(response.status(), if old == code { 204 } else { 401 });
    }
    let replay = server
        .client
        .post(format!("{}/api/auth/setup", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"code":code,"new_password":OTHER_PASSWORD}))
        .send()
        .unwrap();
    assert_eq!(replay.status(), 401);
    let (cookie, person) = server.active_user(&owner_cookie, "disabled_reset", AdminRole::Admin);
    let token = personal_token(&server, &cookie, OTHER_PASSWORD);
    let id = person["user"]["id"].as_str().unwrap();
    assert_eq!(
        mutation(
            &server,
            &owner_cookie,
            &owner,
            reqwest::Method::PATCH,
            &format!("/api/admin/users/{id}"),
            serde_json::json!({"disable":true,"current_password":PASSWORD})
        )
        .status(),
        200
    );
    let reset = mutation(
        &server,
        &owner_cookie,
        &owner,
        reqwest::Method::POST,
        &format!("/api/admin/users/{id}/password-reset"),
        serde_json::json!({"current_password":PASSWORD}),
    );
    assert_eq!(reset.status(), 201);
    let reset: serde_json::Value = reset.json().unwrap();
    assert_eq!(session_status(&server, &cookie), 401);
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .bearer_auth(token.secret.expose_for_delivery())
            .send()
            .unwrap()
            .status(),
        401
    );
    let new_password = "Restored HTTP fixture passphrase 92!";
    let claim = server
        .client
        .post(format!("{}/api/auth/setup", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"code":reset["reset"]["code"],"new_password":new_password}))
        .send()
        .unwrap();
    assert_eq!(claim.status(), 204);
    assert!(!claim.headers().contains_key("set-cookie"));
    for (password, status) in [(OTHER_PASSWORD, 401), (new_password, 200)] {
        assert_eq!(
            server
                .client
                .post(format!("{}/api/auth/login", server.origin))
                .header("Origin", &server.origin)
                .json(&serde_json::json!({"username":"disabled_reset","password":password}))
                .send()
                .unwrap()
                .status(),
            status
        );
    }
    assert_eq!(session_status(&server, &owner_cookie), 200);
}

#[test]
fn owner_http_last_owner_guards_and_successful_self_demotion_clear_only_revoked_cookie() {
    let server = Server::personal();
    let (cookie, owner) = server.login();
    let id = owner["user"]["id"].as_str().unwrap();
    for (method, path, fields) in [
        (
            reqwest::Method::PATCH,
            format!("/api/admin/users/{id}"),
            serde_json::json!({"role":"admin","current_password":PASSWORD}),
        ),
        (
            reqwest::Method::PATCH,
            format!("/api/admin/users/{id}"),
            serde_json::json!({"disable":true,"current_password":PASSWORD}),
        ),
        (
            reqwest::Method::POST,
            format!("/api/admin/users/{id}/password-reset"),
            serde_json::json!({"current_password":PASSWORD}),
        ),
    ] {
        let response = mutation(&server, &cookie, &owner, method, &path, fields);
        assert_eq!(response.status(), 409);
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(
            response.json::<serde_json::Value>().unwrap()["error"],
            "last_owner"
        );
        assert_eq!(session_status(&server, &cookie), 200);
    }
    let (other_cookie, _) = server.active_user(&cookie, "second_owner", AdminRole::Owner);
    let unchanged = mutation(
        &server,
        &cookie,
        &owner,
        reqwest::Method::PATCH,
        &format!("/api/admin/users/{id}"),
        serde_json::json!({"role":"owner","current_password":PASSWORD}),
    );
    assert_eq!(unchanged.status(), 200);
    assert!(!unchanged.headers().contains_key("set-cookie"));
    // This shared fixture intentionally retains a future-created credential. A security
    // change must reject clock-skewed revocation rather than manufacture ended_at < created_at.
    let skewed = mutation(
        &server,
        &cookie,
        &owner,
        reqwest::Method::PATCH,
        &format!("/api/admin/users/{id}"),
        serde_json::json!({"role":"admin","current_password":PASSWORD}),
    );
    assert_eq!(skewed.status(), 409);
    assert_eq!(
        skewed.json::<serde_json::Value>().unwrap()["error"],
        "state_conflict"
    );
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    assert_eq!(
        connection
            .execute(
                "DELETE FROM admin_credentials WHERE credential_id=?1",
                [FUTURE_LOOKUP]
            )
            .unwrap(),
        1
    );
    let demoted = mutation(
        &server,
        &cookie,
        &owner,
        reqwest::Method::PATCH,
        &format!("/api/admin/users/{id}"),
        serde_json::json!({"role":"admin","current_password":PASSWORD}),
    );
    assert_eq!(demoted.status(), 200);
    assert!(
        demoted.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(session_status(&server, &cookie), 401);
    assert_eq!(session_status(&server, &other_cookie), 200);
}

#[test]
fn owner_http_nonowners_cannot_create_change_or_reset_even_themselves() {
    let server = Server::personal();
    let (cookie, _) = server.login();
    for (name, role) in [
        ("api_admin", AdminRole::Admin),
        ("api_operator", AdminRole::Operator),
        ("api_viewer", AdminRole::Viewer),
    ] {
        let (other, person) = server.active_user(&cookie, name, role);
        let id = person["user"]["id"].as_str().unwrap();
        for (method, path, body) in [
            (
                reqwest::Method::POST,
                "/api/admin/users".to_owned(),
                serde_json::json!({"username":"forbidden_new","display_name":"Forbidden","role":"owner","current_password":OTHER_PASSWORD}),
            ),
            (
                reqwest::Method::PATCH,
                format!("/api/admin/users/{id}"),
                serde_json::json!({"role":"owner","current_password":OTHER_PASSWORD}),
            ),
            (
                reqwest::Method::POST,
                format!("/api/admin/users/{id}/password-reset"),
                serde_json::json!({"current_password":OTHER_PASSWORD}),
            ),
        ] {
            let response = mutation(&server, &other, &person, method, &path, body);
            assert_eq!(response.status(), 403);
            assert_eq!(
                response.json::<serde_json::Value>().unwrap()["error"],
                "forbidden"
            );
        }
        assert_eq!(session_status(&server, &other), 200);
    }
    let store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    assert!(
        store
            .account_by_username(&AdminUsername::parse("forbidden_new").unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn owner_http_audit_failure_rolls_back_all_three_mutations_without_private_errors() {
    let server = Server::personal();
    let (cookie, owner) = server.login();
    let (other, person) = server.active_user(&cookie, "rollback_person", AdminRole::Operator);
    let id = person["user"]["id"].as_str().unwrap();
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    let rows = || {
        connection.query_row("SELECT (SELECT count(*) FROM admin_accounts),(SELECT count(*) FROM admin_credentials),(SELECT count(*) FROM audit_events)",[],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?))).unwrap()
    };
    let before = rows();
    connection.execute_batch("CREATE TRIGGER fixture_account_audit_fault BEFORE INSERT ON audit_events WHEN NEW.action IN ('admin_account_created','admin_account_updated','admin_password_reset_requested') BEGIN SELECT RAISE(ABORT,'fixture sensitive account diagnostic'); END;").unwrap();
    for (method, path, body) in [
        (
            reqwest::Method::POST,
            "/api/admin/users".to_owned(),
            serde_json::json!({"username":"rollback_new","display_name":"Rollback","role":"viewer","current_password":PASSWORD}),
        ),
        (
            reqwest::Method::PATCH,
            format!("/api/admin/users/{id}"),
            serde_json::json!({"role":"viewer","current_password":PASSWORD}),
        ),
        (
            reqwest::Method::POST,
            format!("/api/admin/users/{id}/password-reset"),
            serde_json::json!({"current_password":PASSWORD}),
        ),
    ] {
        let response = mutation(&server, &cookie, &owner, method, &path, body);
        assert_eq!(response.status(), 503);
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(
            response.text().unwrap(),
            "{\"error\":\"authentication_unavailable\"}\n"
        );
        assert_eq!(rows(), before);
        assert_eq!(session_status(&server, &other), 200);
    }
    connection
        .execute_batch("DROP TRIGGER fixture_account_audit_fault;")
        .unwrap();
    let response = mutation(
        &server,
        &cookie,
        &owner,
        reqwest::Method::PATCH,
        &format!("/api/admin/users/{id}"),
        serde_json::json!({"role":"viewer","current_password":PASSWORD}),
    );
    assert_eq!(response.status(), 200);
    assert_eq!(session_status(&server, &other), 401);
}
