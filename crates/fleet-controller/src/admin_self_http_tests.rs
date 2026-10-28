//! Self-credential acceptance with synthetic identities and actual owned HTTP workers.

use super::account_mutations::{mutation, personal_token, session_status};
use super::*;

const OTHER_PASSWORD: &str = "Other HTTP fixture passphrase 51!";

#[test]
fn personal_token_http_query_positions_are_strict_and_scoped_to_subject_and_purpose() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) = server.active_user(&owner_cookie, "cursor_person", AdminRole::Viewer);
    personal_token(&server, &cookie, OTHER_PASSWORD);
    personal_token(&server, &cookie, OTHER_PASSWORD);
    let read = |query: &str| {
        server
            .client
            .get(format!("{}/api/auth/tokens{query}", server.origin))
            .header("Cookie", &cookie)
            .send()
            .unwrap()
    };
    let page = read("?limit=1");
    assert_eq!(page.status(), 200);
    let page: serde_json::Value = page.json().unwrap();
    let cursor = page["next_cursor"].as_str().unwrap();
    for query in [
        "?",
        "?limit=0",
        "?limit=101",
        "?limit=1000",
        "?limit=1&limit=2",
        "?limit=1&%6cimit=2",
        "?after=",
        "?after=invalid",
        "?limit=%GG",
        "?user_id=spoof",
    ] {
        assert_eq!(read(query).status(), 400);
    }
    let original: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(cursor).unwrap()).unwrap();
    for (field, value) in [
        ("v", serde_json::json!(2)),
        ("purpose", serde_json::json!("owner_accounts")),
        (
            "owner",
            serde_json::json!("usr_00000000000000000000000000000000"),
        ),
        ("after", serde_json::json!("invalid")),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut cursor = original.clone();
        cursor[field] = value;
        let cursor = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cursor).unwrap());
        assert_eq!(read(&format!("?after={cursor}")).status(), 400);
    }
    let foreign = server
        .client
        .get(format!("{}/api/auth/tokens", server.origin))
        .header("Cookie", &owner_cookie)
        .query(&[("after", cursor)])
        .send()
        .unwrap();
    assert_eq!(foreign.status(), 400);
    let roster = server
        .client
        .get(format!("{}/api/admin/users?limit=1", server.origin))
        .header("Cookie", &owner_cookie)
        .send()
        .unwrap();
    assert_eq!(roster.status(), 200);
    let roster: serde_json::Value = roster.json().unwrap();
    let wrong_purpose = server
        .client
        .get(format!("{}/api/auth/tokens", server.origin))
        .header("Cookie", &owner_cookie)
        .query(&[("after", roster["next_cursor"].as_str().unwrap())])
        .send()
        .unwrap();
    assert_eq!(wrong_purpose.status(), 400);
    assert_eq!(
        server
            .client
            .get(format!("{}/api/auth/tokens", server.origin))
            .header("Cookie", &cookie)
            .json(&serde_json::json!({}))
            .send()
            .unwrap()
            .status(),
        400
    );
    let id = page["items"][0]["id"].as_str().unwrap();
    assert_eq!(
        mutation(
            &server,
            &cookie,
            &profile,
            reqwest::Method::POST,
            &format!("/api/auth/tokens/{id}"),
            serde_json::json!({"current_password":OTHER_PASSWORD})
        )
        .status(),
        404,
        "an unsupported route must never mint a token"
    );
    assert_eq!(
        mutation(
            &server,
            &cookie,
            &profile,
            reqwest::Method::DELETE,
            &format!("/api/auth/tokens/{id}"),
            serde_json::json!({"user_id":"spoof"})
        )
        .status(),
        400
    );
}

#[test]
fn personal_token_http_scopes_before_corrupt_foreign_decode_and_rejects_corrupt_lookahead() {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) = server.active_user(&owner_cookie, "scope_person", AdminRole::Viewer);
    let first = personal_token(&server, &cookie, OTHER_PASSWORD);
    let second = personal_token(&server, &cookie, OTHER_PASSWORD);
    let foreign = personal_token(&server, &owner_cookie, PASSWORD);
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    connection
        .execute(
            "UPDATE admin_credentials SET label=char(1) WHERE credential_id=?1",
            [foreign.id.as_str()],
        )
        .unwrap();
    let web_id: String = connection
        .query_row(
            "SELECT credential_id FROM admin_credentials WHERE kind='web_session' AND user_id=?1",
            [profile["user"]["id"].as_str().unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    let revoke = |id: &str| {
        server
            .client
            .delete(format!("{}/api/auth/tokens/{id}", server.origin))
            .header("Cookie", &cookie)
            .header("Origin", &server.origin)
            .header("X-Fleet-CSRF", profile["csrf_token"].as_str().unwrap())
            .send()
            .unwrap()
    };
    for id in [
        foreign.id.as_str(),
        web_id.as_str(),
        "crd_00000000000000000000000000000000",
    ] {
        let response = revoke(id);
        assert_eq!(response.status(), 404);
        assert_eq!(response.text().unwrap(), "{\"error\":\"not_found\"}\n");
    }
    let read = || {
        server
            .client
            .get(format!("{}/api/auth/tokens?limit=1", server.origin))
            .header("Cookie", &cookie)
            .send()
            .unwrap()
    };
    assert_eq!(
        read().status(),
        200,
        "a corrupt foreign row is outside this query's semantic decoding"
    );
    let high = if first.id > second.id {
        first.id.as_str()
    } else {
        second.id.as_str()
    };
    connection
        .execute(
            "UPDATE admin_credentials SET label=char(1) WHERE credential_id=?1",
            [high],
        )
        .unwrap();
    let broken = read();
    assert_eq!(broken.status(), 503);
    assert_eq!(
        broken.text().unwrap(),
        "{\"error\":\"authentication_unavailable\"}\n",
        "invalid lookahead must not expose a partial page"
    );
    connection
        .execute(
            "UPDATE admin_credentials SET label=NULL WHERE credential_id IN (?1,?2)",
            rusqlite::params![high, foreign.id.as_str()],
        )
        .unwrap();
    assert_eq!(read().status(), 200);
    connection.execute("UPDATE admin_credentials SET state='revoked',ended_at=created_at WHERE credential_id=?1",[high]).unwrap();
    let before: i64 = connection
        .query_row("SELECT count(*) FROM admin_credentials", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        revoke(high).status(),
        404,
        "a retained revoked lookup is already absent to DELETE"
    );
    let after: i64 = connection
        .query_row("SELECT count(*) FROM admin_credentials", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(session_status(&server, &cookie), 200);
}

#[test]
fn personal_token_http_expired_and_future_rows_are_inactive_without_get_cleanup_or_renewal() {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, _) = server.active_user(&owner_cookie, "inactive_person", AdminRole::Operator);
    let expired = personal_token(&server, &cookie, OTHER_PASSWORD);
    let future = personal_token(&server, &cookie, OTHER_PASSWORD);
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    connection
        .execute(
            "UPDATE admin_credentials SET created_at=?2,expires_at=?3 WHERE credential_id=?1",
            rusqlite::params![expired.id.as_str(), now - 2592001, now - 1],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE admin_credentials SET created_at=?2,expires_at=?3 WHERE credential_id=?1",
            rusqlite::params![future.id.as_str(), now + 3600, now + 3600 + 2592000],
        )
        .unwrap();
    let read = || {
        server
            .client
            .get(format!("{}/api/auth/tokens", server.origin))
            .header("Cookie", &cookie)
            .send()
            .unwrap()
    };
    for _ in 0..2 {
        let response = read();
        assert_eq!(response.status(), 200);
        let page: serde_json::Value = response.json().unwrap();
        let items = page["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|item| item["active"] == false));
        assert!(
            items
                .iter()
                .any(|item| item["id"] == expired.id.as_str() && item["expires_at"] == now - 1)
        );
        assert!(
            items.iter().any(|item| item["id"] == future.id.as_str()
                && item["expires_at"] == now + 3600 + 2592000)
        );
    }
}

#[test]
fn personal_token_http_revoke_audit_failure_preserves_proof_and_immutable_actor_survives_name_and_role_change()
 {
    let server = Server::personal();
    let (owner_cookie, owner) = server.login();
    let (cookie, profile) = server.active_user(&owner_cookie, "audit_person", AdminRole::Operator);
    let id = profile["user"]["id"].as_str().unwrap();
    assert_eq!(
        mutation(
            &server,
            &owner_cookie,
            &owner,
            reqwest::Method::PATCH,
            &format!("/api/admin/users/{id}"),
            serde_json::json!({"display_name":"Renamed human","current_password":PASSWORD})
        )
        .status(),
        200
    );
    assert_eq!(
        mutation(
            &server,
            &owner_cookie,
            &owner,
            reqwest::Method::PATCH,
            &format!("/api/admin/users/{id}"),
            serde_json::json!({"role":"viewer","current_password":PASSWORD})
        )
        .status(),
        200
    );
    assert_eq!(session_status(&server, &cookie), 401);
    let login = server
        .client
        .post(format!("{}/api/auth/login", server.origin))
        .header("Origin", &server.origin)
        .json(&serde_json::json!({"username":"audit_person","password":OTHER_PASSWORD}))
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
    let profile: serde_json::Value = login.json().unwrap();
    assert_eq!(profile["user"]["id"], id);
    assert_eq!(profile["user"]["role"], "viewer");
    let token = personal_token(&server, &cookie, OTHER_PASSWORD);
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    connection.execute_batch("CREATE TRIGGER fixture_token_revoke_audit_fault BEFORE INSERT ON audit_events WHEN NEW.action='admin_personal_token_revoked' BEGIN SELECT RAISE(ABORT,'fixture private token revoke diagnostic'); END;").unwrap();
    let revoke = || {
        server
            .client
            .delete(format!(
                "{}/api/auth/tokens/{}",
                server.origin,
                token.id.as_str()
            ))
            .header("Cookie", &cookie)
            .header("Origin", &server.origin)
            .header("X-Fleet-CSRF", profile["csrf_token"].as_str().unwrap())
            .send()
            .unwrap()
    };
    let failed = revoke();
    assert_eq!(failed.status(), 503);
    assert!(!failed.headers().contains_key("set-cookie"));
    assert_eq!(
        failed.text().unwrap(),
        "{\"error\":\"authentication_unavailable\"}\n"
    );
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .bearer_auth(token.secret.expose_for_delivery())
            .send()
            .unwrap()
            .status(),
        200
    );
    connection
        .execute_batch("DROP TRIGGER fixture_token_revoke_audit_fault;")
        .unwrap();
    assert_eq!(revoke().status(), 204);
    let mut statement=connection.prepare("SELECT actor FROM audit_events WHERE action IN ('admin_personal_token_created','admin_personal_token_revoked') AND target=?1 ORDER BY id").unwrap();
    let actors = statement
        .query_map([token.id.as_str()], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        actors,
        vec![id.to_owned(), id.to_owned()],
        "display names never replace immutable audit actors"
    );
    assert_eq!(session_status(&server, &cookie), 200);
}

#[test]
fn personal_token_http_metadata_is_self_only_bounded_proof_free_and_read_only() {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) = server.active_user(&owner_cookie, "metadata_viewer", AdminRole::Viewer);
    let first = personal_token(&server, &cookie, OTHER_PASSWORD);
    let second = personal_token(&server, &cookie, OTHER_PASSWORD);
    let foreign = personal_token(&server, &owner_cookie, PASSWORD);
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    let counts = || {
        connection.query_row("SELECT (SELECT count(*) FROM admin_credentials),(SELECT count(*) FROM audit_events)",[],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?))).unwrap()
    };
    let before = counts();
    let response = server
        .client
        .get(format!("{}/api/auth/tokens?limit=1", server.origin))
        .header("Cookie", &cookie)
        .send()
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "current viewer must reach its actual token metadata endpoint"
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(!response.headers().contains_key("set-cookie"));
    let page: serde_json::Value = response.json().unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    let cursor = page["next_cursor"].as_str().unwrap();
    let next = server
        .client
        .get(format!("{}/api/auth/tokens", server.origin))
        .header("Cookie", &cookie)
        .query(&[("limit", "1"), ("after", cursor)])
        .send()
        .unwrap();
    assert_eq!(next.status(), 200);
    let next: serde_json::Value = next.json().unwrap();
    assert!(next["next_cursor"].is_null());
    let items = [&page["items"][0], &next["items"][0]];
    let mut ids = items
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    ids.sort();
    let mut expected = vec![first.id.as_str(), second.id.as_str()];
    expected.sort();
    assert_eq!(ids, expected);
    for item in items {
        let fields = item.as_object().unwrap();
        assert_eq!(fields.len(), 5);
        assert!(fields.keys().all(|key| {
            ["id", "label", "created_at", "expires_at", "active"].contains(&key.as_str())
        }));
        assert_eq!(item["active"], true);
        assert_eq!(
            item["expires_at"].as_i64().unwrap() - item["created_at"].as_i64().unwrap(),
            30 * 24 * 60 * 60
        );
        assert_ne!(item["id"].as_str().unwrap(), foreign.id.as_str());
    }
    assert_eq!(
        counts(),
        before,
        "metadata never cleans, renews or appends audit"
    );
    assert_eq!(session_status(&server, &cookie), 200);
    assert_eq!(profile["user"]["role"], "viewer");
}

#[test]
fn personal_token_http_revoke_selects_only_owned_pat_and_can_revoke_its_own_caller() {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) =
        server.active_user(&owner_cookie, "revoke_operator", AdminRole::Operator);
    let first = personal_token(&server, &cookie, OTHER_PASSWORD);
    let second = personal_token(&server, &cookie, OTHER_PASSWORD);
    let revoke = |id: &str| {
        server
            .client
            .delete(format!("{}/api/auth/tokens/{id}", server.origin))
            .header("Cookie", &cookie)
            .header("Origin", &server.origin)
            .header("X-Fleet-CSRF", profile["csrf_token"].as_str().unwrap())
            .send()
            .unwrap()
    };
    let removed = revoke(first.id.as_str());
    assert_eq!(
        removed.status(),
        204,
        "actual token deletion must succeed for its current owner"
    );
    assert!(!removed.headers().contains_key("set-cookie"));
    assert_eq!(revoke(first.id.as_str()).status(), 404);
    let use_token = |token: &str| {
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .bearer_auth(token)
            .send()
            .unwrap()
            .status()
            .as_u16()
    };
    assert_eq!(use_token(first.secret.expose_for_delivery()), 401);
    assert_eq!(use_token(second.secret.expose_for_delivery()), 200);
    assert_eq!(session_status(&server, &cookie), 200);
    assert_eq!(session_status(&server, &owner_cookie), 200);
    let removed = server
        .client
        .delete(format!(
            "{}/api/auth/tokens/{}",
            server.origin,
            second.id.as_str()
        ))
        .bearer_auth(second.secret.expose_for_delivery())
        .send()
        .unwrap();
    assert_eq!(removed.status(), 204);
    assert!(!removed.headers().contains_key("set-cookie"));
    assert_eq!(use_token(second.secret.expose_for_delivery()), 401);
    assert_eq!(session_status(&server, &cookie), 200);
}

#[test]
fn all_four_roles_manage_only_their_own_password_and_personal_token_without_escalation() {
    let server = Server::personal();
    let (owner_cookie, owner) = server.login();
    let mut people = Vec::new();
    for (username, role) in [
        ("self_admin", AdminRole::Admin),
        ("self_operator", AdminRole::Operator),
        ("self_viewer", AdminRole::Viewer),
    ] {
        let (cookie, profile) = server.active_user(&owner_cookie, username, role);
        people.push((cookie, profile, OTHER_PASSWORD));
    }
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    connection
        .execute(
            "DELETE FROM admin_credentials WHERE credential_id=?1",
            [FUTURE_LOOKUP],
        )
        .unwrap();
    people.push((owner_cookie, owner, PASSWORD));
    for (cookie, profile, password) in people {
        let token = mutation(
            &server,
            &cookie,
            &profile,
            reqwest::Method::POST,
            "/api/auth/tokens",
            serde_json::json!({"current_password":password}),
        );
        assert_eq!(token.status(), 201);
        let token: serde_json::Value = token.json().unwrap();
        let secret = token["token"]["secret"].as_str().unwrap();
        let spare = personal_token(&server, &cookie, password);
        let listed = server
            .client
            .get(format!("{}/api/auth/tokens", server.origin))
            .header("Cookie", &cookie)
            .send()
            .unwrap();
        assert_eq!(listed.status(), 200);
        assert_eq!(
            listed.json::<serde_json::Value>().unwrap()["items"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let removed = server
            .client
            .delete(format!(
                "{}/api/auth/tokens/{}",
                server.origin,
                spare.id.as_str()
            ))
            .header("Cookie", &cookie)
            .header("Origin", &server.origin)
            .header("X-Fleet-CSRF", profile["csrf_token"].as_str().unwrap())
            .send()
            .unwrap();
        assert_eq!(
            removed.status(),
            204,
            "each active role may remove its own selected PAT"
        );
        let new_password = "All roles personal fixture passphrase 79!";
        // Admin uses its PAT; all other roles use cookie+CSRF. Neither can nominate a target.
        let body = serde_json::json!({"current_password":password,"new_password":new_password});
        let changed = if profile["user"]["role"] == "admin" {
            let response = server
                .client
                .post(format!("{}/api/auth/password", server.origin))
                .bearer_auth(secret)
                .json(&body)
                .send()
                .unwrap();
            assert!(!response.headers().contains_key("set-cookie"));
            response
        } else {
            mutation(
                &server,
                &cookie,
                &profile,
                reqwest::Method::POST,
                "/api/auth/password",
                body,
            )
        };
        assert_eq!(changed.status(), 204);
        assert_eq!(session_status(&server, &cookie), 401);
        assert_eq!(
            server
                .client
                .get(format!("{}/api/agents", server.origin))
                .bearer_auth(secret)
                .send()
                .unwrap()
                .status(),
            401
        );
        let login=server.client.post(format!("{}/api/auth/login",server.origin)).header("Origin",&server.origin)
            .json(&serde_json::json!({"username":profile["user"]["username"],"password":new_password})).send().unwrap();
        assert_eq!(login.status(), 200);
        let next: serde_json::Value = login.json().unwrap();
        assert_eq!(next["user"]["id"], profile["user"]["id"]);
        assert_eq!(next["user"]["role"], profile["user"]["role"]);
    }
}

#[test]
fn self_http_rejects_nominated_subjects_roles_invalid_passwords_and_token_labels() {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) = server.active_user(&owner_cookie, "self_invalid", AdminRole::Viewer);
    for body in [
        serde_json::json!({"current_password":OTHER_PASSWORD,"new_password":"Valid uncommitted passphrase 87!","user_id":"spoof"}),
        serde_json::json!({"current_password":OTHER_PASSWORD,"new_password":"Valid uncommitted passphrase 87!","role":"owner"}),
        serde_json::json!({"current_password":OTHER_PASSWORD,"new_password":"short"}),
        serde_json::json!({"current_password":OTHER_PASSWORD,"new_password":null}),
    ] {
        assert_eq!(
            mutation(
                &server,
                &cookie,
                &profile,
                reqwest::Method::POST,
                "/api/auth/password",
                body
            )
            .status(),
            400
        );
    }
    for label in [
        serde_json::Value::Null,
        serde_json::json!(""),
        serde_json::json!(" \t"),
        serde_json::json!("x".repeat(257)),
        serde_json::json!("bad\nlabel"),
    ] {
        assert_eq!(
            mutation(
                &server,
                &cookie,
                &profile,
                reqwest::Method::POST,
                "/api/auth/tokens",
                serde_json::json!({"current_password":OTHER_PASSWORD,"label":label})
            )
            .status(),
            400
        );
    }
    assert_eq!(
        mutation(
            &server,
            &cookie,
            &profile,
            reqwest::Method::POST,
            "/api/auth/tokens",
            serde_json::json!({"current_password":OTHER_PASSWORD,"user_id":"spoof"})
        )
        .status(),
        400
    );
    for (path, body) in [
        (
            "/api/auth/password",
            serde_json::json!({"current_password":"wrong fixture passphrase","new_password":"Valid uncommitted passphrase 87!"}),
        ),
        (
            "/api/auth/tokens",
            serde_json::json!({"current_password":"wrong fixture passphrase"}),
        ),
    ] {
        assert_eq!(
            mutation(
                &server,
                &cookie,
                &profile,
                reqwest::Method::POST,
                path,
                body
            )
            .status(),
            401
        );
    }
    assert_eq!(session_status(&server, &cookie), 200);
    assert_eq!(session_status(&server, &owner_cookie), 200);
}

#[test]
fn self_http_token_limit_is_distinct_and_expired_lookup_cleanup_allows_fresh_issuance() {
    use fleet_application::admin_identity::*;
    use fleet_domain::{AdminCredential, AdminCredentialKind};
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) = server.active_user(&owner_cookie, "quota_person", AdminRole::Operator);
    let mint = || {
        mutation(
            &server,
            &cookie,
            &profile,
            reqwest::Method::POST,
            "/api/auth/tokens",
            serde_json::json!({"current_password":OTHER_PASSWORD}),
        )
    };
    let first = mint();
    assert_eq!(first.status(), 201);
    let first: serde_json::Value = first.json().unwrap();
    let mut store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    let id =
        fleet_domain::AdminCredentialId::parse(first["token"]["id"].as_str().unwrap()).unwrap();
    let original = store.credential_by_id(&id).unwrap().unwrap().snapshot();
    let mut expire = None;
    store
        .identity_transaction(|tx| {
            for _ in 0..15 {
                let material =
                    AdminTokenCrypto::system().credential(AdminCredentialKind::PersonalToken)?;
                let row = AdminCredential::issue_personal_token(
                    material.id,
                    material.digest,
                    original.binding.clone(),
                    original.created_at,
                    None,
                )
                .unwrap()
                .snapshot();
                expire = Some(row.id.clone());
                tx.insert_credential(&row)?;
            }
            Ok(())
        })
        .unwrap();
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    let audits = || {
        connection
            .query_row(
                "SELECT count(*) FROM audit_events WHERE action='admin_personal_token_created'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    };
    let before = audits();
    let full = mint();
    assert_eq!(full.status(), 429);
    assert_eq!(
        full.json::<serde_json::Value>().unwrap()["error"],
        "token_limit"
    );
    assert_eq!(audits(), before);
    connection
        .execute(
            "UPDATE admin_credentials SET created_at=?2,expires_at=?3 WHERE credential_id=?1",
            rusqlite::params![
                expire.unwrap().as_str(),
                original.created_at - 30 * 24 * 60 * 60 - 1,
                original.created_at - 1
            ],
        )
        .unwrap();
    let fresh = mint();
    assert_eq!(fresh.status(), 201);
    assert_eq!(audits(), before + 1);
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .bearer_auth(first["token"]["secret"].as_str().unwrap())
            .send()
            .unwrap()
            .status(),
        200
    );
}

#[test]
fn self_http_password_and_token_audit_failures_leave_old_proofs_and_account_intact() {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) = server.active_user(&owner_cookie, "self_rollback", AdminRole::Operator);
    let token = personal_token(&server, &cookie, OTHER_PASSWORD);
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    let snapshot = || {
        connection.query_row("SELECT (SELECT count(*) FROM admin_credentials),(SELECT count(*) FROM audit_events),(SELECT record_revision FROM admin_accounts WHERE username='self_rollback')",[],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?))).unwrap()
    };
    let before = snapshot();
    connection.execute_batch("CREATE TRIGGER fixture_self_audit_fault BEFORE INSERT ON audit_events WHEN NEW.action IN ('admin_password_changed','admin_personal_token_created') BEGIN SELECT RAISE(ABORT,'fixture private self audit diagnostic'); END;").unwrap();
    for (path, body) in [
        (
            "/api/auth/password",
            serde_json::json!({"current_password":OTHER_PASSWORD,"new_password":"Uncommitted self fixture passphrase 99!"}),
        ),
        (
            "/api/auth/tokens",
            serde_json::json!({"current_password":OTHER_PASSWORD}),
        ),
    ] {
        let response = mutation(
            &server,
            &cookie,
            &profile,
            reqwest::Method::POST,
            path,
            body,
        );
        assert_eq!(response.status(), 503);
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(
            response.text().unwrap(),
            "{\"error\":\"authentication_unavailable\"}\n"
        );
        assert_eq!(snapshot(), before);
        assert_eq!(session_status(&server, &cookie), 200);
    }
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .bearer_auth(token.secret.expose_for_delivery())
            .send()
            .unwrap()
            .status(),
        200
    );
    connection
        .execute_batch("DROP TRIGGER fixture_self_audit_fault;")
        .unwrap();
    assert_eq!(
        mutation(
            &server,
            &cookie,
            &profile,
            reqwest::Method::POST,
            "/api/auth/tokens",
            serde_json::json!({"current_password":OTHER_PASSWORD})
        )
        .status(),
        201
    );
}

#[test]
fn operator_http_changes_own_password_revokes_its_proofs_and_requires_new_login() {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) =
        server.active_user(&owner_cookie, "password_operator", AdminRole::Operator);
    let token = personal_token(&server, &cookie, OTHER_PASSWORD);
    let new_password = "New operator HTTP fixture passphrase 73!";
    let changed = mutation(
        &server,
        &cookie,
        &profile,
        reqwest::Method::POST,
        "/api/auth/password",
        serde_json::json!({"current_password":OTHER_PASSWORD,"new_password":new_password}),
    );
    assert_eq!(
        changed.status(),
        204,
        "an active operator must reach its real password operation"
    );
    assert_eq!(changed.headers()["cache-control"], "no-store");
    assert!(
        changed.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert!(changed.text().unwrap().is_empty());
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
    assert_eq!(session_status(&server, &owner_cookie), 200);
    for (password, status) in [(OTHER_PASSWORD, 401), (new_password, 200)] {
        let login = server
            .client
            .post(format!("{}/api/auth/login", server.origin))
            .header("Origin", &server.origin)
            .json(&serde_json::json!({"username":"password_operator","password":password}))
            .send()
            .unwrap();
        assert_eq!(login.status(), status);
        if status == 200 {
            let session: serde_json::Value = login.json().unwrap();
            assert_eq!(session["user"]["id"], profile["user"]["id"]);
            assert_eq!(session["user"]["role"], "operator");
        }
    }
}

#[test]
fn viewer_http_mints_own_fixed_thirty_day_personal_token_and_uses_it_as_bearer() {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) = server.active_user(&owner_cookie, "token_viewer", AdminRole::Viewer);
    let response = mutation(
        &server,
        &cookie,
        &profile,
        reqwest::Method::POST,
        "/api/auth/tokens",
        serde_json::json!({"current_password":OTHER_PASSWORD,"label":"Viewer fixture laptop"}),
    );
    assert_eq!(
        response.status(),
        201,
        "an active viewer must reach its real PAT issuance operation"
    );
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: serde_json::Value = response.json().unwrap();
    let issued = body["token"].as_object().unwrap();
    assert_eq!(issued.len(), 3);
    let secret = body["token"]["secret"].as_str().unwrap();
    assert!(secret.starts_with("fpat_") && secret.len() == 69);
    let id = fleet_domain::AdminCredentialId::parse(body["token"]["id"].as_str().unwrap()).unwrap();
    let store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    let stored = store.credential_by_id(&id).unwrap().unwrap().snapshot();
    assert_eq!(stored.expires_at - stored.created_at, 30 * 24 * 60 * 60);
    assert_eq!(
        stored.expires_at,
        body["token"]["expires_at"].as_i64().unwrap()
    );
    assert_eq!(
        stored.binding.user_id.as_str(),
        profile["user"]["id"].as_str().unwrap()
    );
    assert_eq!(stored.label.unwrap().as_str(), "Viewer fixture laptop");
    let session = server
        .client
        .get(format!("{}/api/auth/session", server.origin))
        .bearer_auth(secret)
        .send()
        .unwrap();
    assert_eq!(session.status(), 200);
    let session: serde_json::Value = session.json().unwrap();
    assert_eq!(session["user"]["id"], profile["user"]["id"]);
    assert!(session["csrf_token"].is_null());
    assert_eq!(session_status(&server, &cookie), 200);
    assert_eq!(session_status(&server, &owner_cookie), 200);
}
