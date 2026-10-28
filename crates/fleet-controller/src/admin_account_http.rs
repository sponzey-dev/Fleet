//! Owner account HTTP adapters. Application owns authorization and atomic writes;
//! opaque cursor positions and body fields never supply actor authority.

use super::*;
use fleet_domain::{AdminDisplayName, AdminUserId};

pub(super) fn is_route(path: &str) -> bool {
    path == "/api/admin/users" || path.starts_with("/api/admin/users/")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    username: String,
    display_name: String,
    role: String,
    current_password: String,
}

impl Drop for CreateBody {
    fn drop(&mut self) {
        self.current_password.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeBody {
    #[serde(default, deserialize_with = "present_value")]
    display_name: Option<String>,
    #[serde(default, deserialize_with = "present_value")]
    role: Option<String>,
    #[serde(default, deserialize_with = "present_value")]
    disable: Option<bool>,
    current_password: String,
}

impl Drop for ChangeBody {
    fn drop(&mut self) {
        self.current_password.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetBody {
    current_password: String,
}

impl Drop for ResetBody {
    fn drop(&mut self) {
        self.current_password.zeroize();
    }
}

fn grant_json(grant: &IssuedAdminCredential) -> serde_json::Value {
    serde_json::json!({"id":grant.id.as_str(),"expires_at":grant.expires_at,
        "code":grant.secret.expose_for_delivery()})
}

pub(super) async fn handle(
    request: &str,
    mut repository: SharedIdentityRepository,
    actor: AuthenticatedAdmin,
    operation: &AdminAuthOperation,
    runtime: &AdminHttpRuntime,
    policy: &CookiePolicy,
) -> Result<String, HttpFailure> {
    let mut line = request.lines().next().unwrap_or("").split_whitespace();
    let method = line.next().unwrap_or("");
    let path = line.next().unwrap_or("").split('?').next().unwrap_or("");
    if method == "GET" {
        return read(request, &repository, &actor, operation);
    }
    // Owner permission is checked before target lookup or expensive password work.
    let owner = GetAdminAccountMetadata::execute(&repository, &actor, operation, actor.user_id())
        .map_err(|error| failure(error, "session_limit"))?;
    require_json(&RequestHeaders::parse(request)?)?;
    let body = request.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    if body.len() > BODY_LIMIT {
        return Err((413, "request_too_large"));
    }
    let web = actor.credential_kind() == AdminCredentialKind::WebSession;
    if (method, path) == ("POST", "/api/admin/users") {
        let body: CreateBody = serde_json::from_str(body).map_err(|_| (400, "invalid_request"))?;
        let username =
            AdminUsername::parse(&body.username).map_err(|_| (400, "invalid_request"))?;
        let display_name =
            AdminDisplayName::parse(&body.display_name).map_err(|_| (400, "invalid_request"))?;
        let role = AdminRole::parse(&body.role).ok_or((400, "invalid_request"))?;
        let result = password_action(
            runtime,
            operation,
            owner.username.as_str(),
            "session_limit",
            move |operation, client| {
                CreateAdminAccount::execute(
                    &mut repository,
                    &actor,
                    operation,
                    &client.passwords(operation),
                    &AdminTokenCrypto::system(),
                    CreateAdminAccountInput {
                        username,
                        display_name,
                        role,
                        current_password: &body.current_password,
                    },
                )
            },
        )
        .await?;
        return Ok(cookie_response(
            201,
            serde_json::json!({"user":user_json(&result.account),"setup":grant_json(&result.setup)}),
            None,
        ));
    }
    let suffix = path
        .strip_prefix("/api/admin/users/")
        .ok_or((404, "not_found"))?;
    let (id, reset) = suffix
        .strip_suffix("/password-reset")
        .map_or((suffix, false), |id| (id, true));
    if id.contains('/') || !matches!((method, reset), ("PATCH", false) | ("POST", true)) {
        return Err((404, "not_found"));
    }
    let id = AdminUserId::parse(id).map_err(|_| (400, "invalid_request"))?;
    let own = id == *actor.user_id();
    if reset {
        let body: ResetBody = serde_json::from_str(body).map_err(|_| (400, "invalid_request"))?;
        let grant = password_action(
            runtime,
            operation,
            owner.username.as_str(),
            "session_limit",
            move |operation, client| {
                ResetAdminPassword::execute(
                    &mut repository,
                    &actor,
                    operation,
                    &client.passwords(operation),
                    &AdminTokenCrypto::system(),
                    ResetAdminPasswordInput {
                        user_id: id,
                        current_password: &body.current_password,
                    },
                )
            },
        )
        .await?;
        return Ok(cookie_response(
            201,
            serde_json::json!({"reset":grant_json(&grant)}),
            (web && own).then(|| policy.cookie("", 0)),
        ));
    }
    let body: ChangeBody = serde_json::from_str(body).map_err(|_| (400, "invalid_request"))?;
    if body.disable == Some(false)
        || (body.display_name.is_none() && body.role.is_none() && body.disable != Some(true))
    {
        return Err((400, "invalid_request"));
    }
    let display_name = body
        .display_name
        .as_deref()
        .map(AdminDisplayName::parse)
        .transpose()
        .map_err(|_| (400, "invalid_request"))?;
    let role = body
        .role
        .as_deref()
        .map(|value| AdminRole::parse(value).ok_or((400, "invalid_request")))
        .transpose()?;
    let revoke_self =
        web && own && (body.disable == Some(true) || role.is_some_and(|role| role != owner.role));
    let user = password_action(
        runtime,
        operation,
        owner.username.as_str(),
        "session_limit",
        move |operation, client| {
            ChangeAdminAccount::execute(
                &mut repository,
                &actor,
                operation,
                &client.passwords(operation),
                ChangeAdminAccountInput {
                    user_id: id,
                    display_name,
                    role,
                    disable: body.disable == Some(true),
                    current_password: &body.current_password,
                },
            )
        },
    )
    .await?;
    Ok(cookie_response(
        200,
        serde_json::json!({"user":user_json(&user)}),
        revoke_self.then(|| policy.cookie("", 0)),
    ))
}

pub(super) fn read(
    request: &str,
    repository: &SharedIdentityRepository,
    actor: &AuthenticatedAdmin,
    operation: &dyn AdminOperation,
) -> Result<String, HttpFailure> {
    let mut parts = request.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    if method != "GET" {
        return Err((404, "not_found"));
    }
    if request
        .split_once("\r\n\r\n")
        .is_some_and(|(_, body)| !body.is_empty())
    {
        return Err((400, "invalid_request"));
    }
    if path == "/api/admin/users" {
        let (limit, after) = metadata::page_query(query, |value| {
            let position = metadata::decode_cursor(value, actor, "owner_accounts")?;
            AdminUserId::parse(&position).map_err(|_| (400, "invalid_cursor"))
        })?;
        let page = ListAdminAccountMetadata::execute(
            repository,
            actor,
            operation,
            ListAdminAccountMetadataInput {
                after: after.as_ref(),
                limit,
            },
        )
        .map_err(|error| failure(error, "session_limit"))?;
        let next = page
            .next_after
            .as_ref()
            .map(|id| metadata::encode_cursor(id.as_str(), actor, "owner_accounts"))
            .transpose()?;
        Ok(cookie_response(
            200,
            serde_json::json!({"items":page.items.iter().map(user_json).collect::<Vec<_>>(),"next_cursor":next}),
            None,
        ))
    } else {
        if query.is_some() {
            return Err((400, "invalid_request"));
        }
        let id = path
            .strip_prefix("/api/admin/users/")
            .filter(|value| !value.contains('/'))
            .ok_or((404, "not_found"))?;
        let id = AdminUserId::parse(id).map_err(|_| (400, "invalid_request"))?;
        let user = GetAdminAccountMetadata::execute(repository, actor, operation, &id)
            .map_err(|error| failure(error, "session_limit"))?;
        Ok(cookie_response(
            200,
            serde_json::json!({"user":user_json(&user)}),
            None,
        ))
    }
}
