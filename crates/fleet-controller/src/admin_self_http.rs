//! Self-credential HTTP adapters. The authenticated subject is the only target;
//! Application owns proof, current-binding checks and atomic issuance/revocation.

use super::*;
use fleet_domain::{AdminCredentialId, AdminTokenLabel};

pub(super) fn is_route(path: &str) -> bool {
    matches!(path, "/api/auth/password" | "/api/auth/tokens")
        || path.starts_with("/api/auth/tokens/")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordBody {
    current_password: String,
    new_password: String,
}

impl Drop for PasswordBody {
    fn drop(&mut self) {
        self.current_password.zeroize();
        self.new_password.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBody {
    current_password: String,
    #[serde(default, deserialize_with = "present_value")]
    label: Option<String>,
}

impl Drop for TokenBody {
    fn drop(&mut self) {
        self.current_password.zeroize();
    }
}

pub(super) async fn handle(
    request: &str,
    mut repository: SharedIdentityRepository,
    actor: AuthenticatedAdmin,
    operation: &AdminAuthOperation,
    runtime: &AdminHttpRuntime,
    policy: &CookiePolicy,
) -> Result<String, HttpFailure> {
    let mut parts = request.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    let body = request.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    if method == "GET" && path == "/api/auth/tokens" {
        if !body.is_empty() {
            return Err((400, "invalid_request"));
        }
        let (limit, after) = metadata::page_query(query, |value| {
            let position = metadata::decode_cursor(value, &actor, "own_personal_tokens")?;
            AdminCredentialId::parse(&position).map_err(|_| (400, "invalid_cursor"))
        })?;
        let page = ListOwnAdminPersonalTokens::execute(
            &repository,
            &actor,
            operation,
            ListOwnAdminPersonalTokensInput {
                after: after.as_ref(),
                limit,
            },
        )
        .map_err(|error| failure(error, "token_limit"))?;
        let next = page
            .next_after
            .as_ref()
            .map(|id| metadata::encode_cursor(id.as_str(), &actor, "own_personal_tokens"))
            .transpose()?;
        let items = page
            .items
            .iter()
            .map(|item| {
                serde_json::json!({
                    "id": item.id.as_str(), "label": item.label.as_ref().map(|label|label.as_str()),
                    "created_at":item.created_at,"expires_at":item.expires_at,"active":item.active,
                })
            })
            .collect::<Vec<_>>();
        return Ok(cookie_response(
            200,
            serde_json::json!({"items":items,"next_cursor":next}),
            None,
        ));
    }
    if method == "DELETE"
        && let Some(id) = path.strip_prefix("/api/auth/tokens/")
    {
        if id.contains('/') {
            return Err((404, "not_found"));
        }
        if !body.is_empty() {
            return Err((400, "invalid_request"));
        }
        let id = AdminCredentialId::parse(id).map_err(|_| (400, "invalid_request"))?;
        RevokeOwnAdminPersonalToken::execute(&mut repository, &actor, operation, &id)
            .map_err(|error| failure(error, "token_limit"))?;
        return Ok(cookie_response(204, serde_json::Value::Null, None));
    }
    if method != "POST" || !matches!(path, "/api/auth/password" | "/api/auth/tokens") {
        return Err((404, "not_found"));
    }
    require_json(&RequestHeaders::parse(request)?)?;
    if body.len() > BODY_LIMIT {
        return Err((413, "request_too_large"));
    }
    // The current actor was resolved by Application; only its canonical username keys
    // password admission. The mutation use case rechecks that actor at commit.
    let username = repository
        .account_by_id(actor.user_id())
        .map_err(|error| failure(error, "token_limit"))?
        .ok_or((401, "unauthorized"))?
        .snapshot()
        .username;
    let web = actor.credential_kind() == AdminCredentialKind::WebSession;
    if path == "/api/auth/password" {
        let body: PasswordBody =
            serde_json::from_str(body).map_err(|_| (400, "invalid_request"))?;
        password_action(
            runtime,
            operation,
            username.as_str(),
            "session_limit",
            move |operation, client| {
                ChangeOwnAdminPassword::execute(
                    &mut repository,
                    &actor,
                    operation,
                    &client.passwords(operation),
                    ChangeOwnAdminPasswordInput {
                        current_password: &body.current_password,
                        new_password: &body.new_password,
                    },
                )
            },
        )
        .await?;
        return Ok(cookie_response(
            204,
            serde_json::Value::Null,
            web.then(|| policy.cookie("", 0)),
        ));
    }
    let body: TokenBody = serde_json::from_str(body).map_err(|_| (400, "invalid_request"))?;
    let label = body
        .label
        .as_deref()
        .map(AdminTokenLabel::parse)
        .transpose()
        .map_err(|_| (400, "invalid_request"))?;
    let token = password_action(
        runtime,
        operation,
        username.as_str(),
        "token_limit",
        move |operation, client| {
            CreateAdminPersonalToken::execute(
                &mut repository,
                &actor,
                operation,
                &client.passwords(operation),
                &AdminTokenCrypto::system(),
                CreateAdminPersonalTokenInput {
                    current_password: &body.current_password,
                    label,
                },
            )
        },
    )
    .await?;
    Ok(cookie_response(
        201,
        serde_json::json!({"token":{"id":token.id.as_str(),
        "expires_at":token.expires_at,"secret":token.secret.expose_for_delivery()}}),
        None,
    ))
}
