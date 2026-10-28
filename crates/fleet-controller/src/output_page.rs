//! Authorized output-read HTTP mapping and opaque cursor serialization. The
//! cursor is an untrusted position; permission and persisted scope remain required.

use super::no_store;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fleet_application::JobOutputStream;
use fleet_application::output_read::{
    OutputHistory, OutputPage, OutputPageRepository, OutputReadCursor, OutputReadError,
    OutputReadLimits, OutputReadScope, ReadJobOutputPage,
};
use fleet_domain::{AgentId, JobId, JobStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

struct PageRequest {
    scope: OutputReadScope,
    limits: OutputReadLimits,
    after: Option<OutputReadCursor>,
}

fn parse_request(raw_path: &str) -> Result<PageRequest, OutputReadError> {
    let (path, query) = raw_path.split_once('?').unwrap_or((raw_path, ""));
    let job = path
        .strip_prefix("/api/jobs/")
        .and_then(|p| p.strip_suffix("/output-page"))
        .filter(|p| !p.is_empty() && !p.contains('/'))
        .ok_or(OutputReadError::InvalidCursor)?;
    // The existing strict decoder implements form-query '+' semantics. A path
    // segment preserves literal plus signs before using its percent/UTF-8 check.
    let job = decode_query(&job.replace('+', "%2B"))?;
    let mut fields = BTreeMap::new();
    if !query.is_empty() {
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').ok_or(OutputReadError::InvalidCursor)?;
            let key = decode_query(key)?;
            if !matches!(
                key.as_str(),
                "after" | "agent_id" | "stream" | "limit" | "max_bytes"
            ) || fields.insert(key, decode_query(value)?).is_some()
            {
                return Err(OutputReadError::InvalidCursor);
            }
        }
    }
    let scope = OutputReadScope {
        job_id: JobId::new(job).map_err(|_| OutputReadError::InvalidCursor)?,
        agent_id: fields
            .get("agent_id")
            .map(|v| AgentId::new(v.clone()).map_err(|_| OutputReadError::InvalidCursor))
            .transpose()?,
        stream: fields
            .get("stream")
            .map(|v| match v.as_str() {
                "stdout" => Ok(JobOutputStream::Stdout),
                "stderr" => Ok(JobOutputStream::Stderr),
                _ => Err(OutputReadError::InvalidCursor),
            })
            .transpose()?,
    };
    let limits = OutputReadLimits::new(
        query_integer(fields.get("limit"), 128)?,
        query_integer(fields.get("max_bytes"), 65536)?,
    )?;
    let after = fields
        .get("after")
        .map(|text| decode_cursor(&scope, text))
        .transpose()?;
    Ok(PageRequest {
        scope,
        limits,
        after,
    })
}

fn decode_query(text: &str) -> Result<String, OutputReadError> {
    super::decode_catalog_query_value(text).map_err(|_| OutputReadError::InvalidCursor)
}
fn query_integer(text: Option<&String>, default: usize) -> Result<usize, OutputReadError> {
    let Some(text) = text else { return Ok(default) };
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(OutputReadError::InvalidLimit);
    }
    text.parse().map_err(|_| OutputReadError::InvalidLimit)
}

fn scope_digest(scope: &OutputReadScope) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"fleet.output-read.scope.v1");
    let stream = scope.stream.map(|s| match s {
        JobOutputStream::Stdout => "stdout",
        JobOutputStream::Stderr => "stderr",
    });
    for (tag, value) in [
        (b'j', Some(scope.job_id.as_str())),
        (b'a', scope.agent_id.as_ref().map(AgentId::as_str)),
        (b's', stream),
    ] {
        hash.update([tag]);
        hash.update([u8::from(value.is_some())]);
        if let Some(value) = value {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
    }
    hash.finalize().into()
}
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(text: &str) -> Result<[u8; 32], OutputReadError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(OutputReadError::InvalidCursor);
    }
    let mut bytes = [0; 32];
    for (i, value) in bytes.iter_mut().enumerate() {
        *value = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| OutputReadError::InvalidCursor)?;
    }
    Ok(bytes)
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Fence {
    Closed(String),
    Open,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorWire {
    s: String,
    e: String,
    g: String,
    r: String,
    o: String,
    f: Fence,
}

fn cursor_integer(text: &str) -> Result<i64, OutputReadError> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(OutputReadError::InvalidCursor);
    }
    text.parse().map_err(|_| OutputReadError::InvalidCursor)
}

fn encode_cursor(cursor: &OutputReadCursor) -> Result<String, OutputReadError> {
    let wire = CursorWire {
        s: hex(&scope_digest(cursor.scope())),
        e: hex(cursor.store_stamp()),
        g: cursor.generation().to_string(),
        r: cursor.row().to_string(),
        o: cursor.offset().to_string(),
        f: cursor
            .fence()
            .map(|n| Fence::Closed(n.to_string()))
            .unwrap_or(Fence::Open),
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_| OutputReadError::Unavailable)?;
    if bytes.len() > 2048 || !bytes.is_ascii() {
        return Err(OutputReadError::Unavailable);
    }
    Ok(format!("op1.{}", URL_SAFE_NO_PAD.encode(bytes)))
}
fn decode_cursor(scope: &OutputReadScope, text: &str) -> Result<OutputReadCursor, OutputReadError> {
    if text.len() > 2735 {
        return Err(OutputReadError::InvalidCursor);
    }
    let encoded = text
        .strip_prefix("op1.")
        .ok_or(OutputReadError::InvalidCursor)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| OutputReadError::InvalidCursor)?;
    if bytes.len() > 2048 || !bytes.is_ascii() || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(OutputReadError::InvalidCursor);
    }
    let wire: CursorWire =
        serde_json::from_slice(&bytes).map_err(|_| OutputReadError::InvalidCursor)?;
    if digest(&wire.s)? != scope_digest(scope) {
        return Err(OutputReadError::ScopeMismatch);
    }
    let fence = match wire.f {
        Fence::Closed(s) => Some(cursor_integer(&s)?),
        Fence::Open => None,
    };
    OutputReadCursor::new(
        scope.clone(),
        digest(&wire.e)?,
        cursor_integer(&wire.g)?,
        cursor_integer(&wire.r)?,
        cursor_integer(&wire.o)?,
        fence,
    )
}

impl OutputPageRepository for super::ControllerStoreRef<'_> {
    fn read_output_page(
        &self,
        scope: &OutputReadScope,
        after: Option<&OutputReadCursor>,
        limits: OutputReadLimits,
    ) -> Result<OutputPage, OutputReadError> {
        match self {
            Self::Sqlite(store) => store.read_output_page(scope, after, limits),
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => Err(OutputReadError::Unavailable),
        }
    }
}

#[derive(Serialize)]
struct FragmentResponse {
    chunk_key: String,
    agent_id: String,
    stream: &'static str,
    sequence: String,
    offset_bytes: String,
    total_bytes: String,
    data: String,
    chunk_complete: bool,
}
#[derive(Serialize)]
struct PageResponse {
    items: Vec<FragmentResponse>,
    next_after: String,
    has_more: bool,
    caught_up: bool,
    history: &'static str,
    job_status: &'static str,
}

fn serialize_page(page: OutputPage) -> Result<String, OutputReadError> {
    let next_after = encode_cursor(&page.next)?;
    let items = page
        .items
        .into_iter()
        .map(|f| {
            let position = f.position();
            FragmentResponse {
                chunk_key: position.chunk_key.to_string(),
                agent_id: f.agent_id().as_str().to_owned(),
                stream: match f.stream() {
                    JobOutputStream::Stdout => "stdout",
                    JobOutputStream::Stderr => "stderr",
                },
                sequence: position.sequence.to_string(),
                offset_bytes: position.offset_bytes.to_string(),
                total_bytes: position.total_bytes.to_string(),
                data: f.data().to_owned(),
                chunk_complete: f.chunk_complete(),
            }
        })
        .collect();
    let body = PageResponse {
        items,
        next_after,
        has_more: page.has_more,
        caught_up: page.caught_up,
        history: match page.history {
            OutputHistory::Tracked => "tracked",
            OutputHistory::Unknown => "unknown",
            OutputHistory::Pruned => "pruned",
        },
        job_status: match page.job_status {
            JobStatus::Draft => "draft",
            JobStatus::PendingApproval => "pending_approval",
            JobStatus::Queued => "queued",
            JobStatus::Running => "running",
            JobStatus::PartialSuccess => "partial_success",
            JobStatus::Success => "success",
            JobStatus::Failed => "failed",
            JobStatus::Canceled => "canceled",
            JobStatus::Expired => "expired",
        },
    };
    let mut text = serde_json::to_string(&body).map_err(|_| OutputReadError::Unavailable)?;
    text.push('\n');
    if text.len() > 2 * 1024 * 1024 {
        return Err(OutputReadError::Unavailable);
    }
    Ok(text)
}

fn reply(status: u16, body: &str) -> String {
    no_store(super::response(status, "application/json", body))
}

fn error_reply(error: OutputReadError) -> String {
    let (status, code) = match error {
        OutputReadError::InvalidLimit
        | OutputReadError::ScopeMismatch
        | OutputReadError::InvalidCursor => (400, "invalid_output_cursor"),
        OutputReadError::StaleCursor => (409, "output_cursor_stale"),
        OutputReadError::JobNotFound => (404, "not_found"),
        OutputReadError::MetadataTooLarge => (413, "output_metadata_too_large"),
        OutputReadError::Unavailable => (500, "output_read_unavailable"),
    };
    reply(status, &format!("{{\"error\":\"{code}\"}}\n"))
}

/// The parent route must authenticate and require JobRead before calling this.
pub(super) fn handle(raw_path: &str, store: super::ControllerStoreRef<'_>) -> String {
    let request = match parse_request(raw_path) {
        Ok(request) => request,
        Err(_) => return reply(400, "{\"error\":\"invalid_output_query\"}\n"),
    };
    let result = ReadJobOutputPage::execute(
        &store,
        &request.scope,
        request.after.as_ref(),
        request.limits,
    )
    .and_then(serialize_page);
    match result {
        Ok(body) => reply(200, &body),
        Err(error) => error_reply(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use fleet_domain::{AgentId, ApprovalRequirement, Job, JobId, TaskRisk};
    use std::time::Duration;

    fn scope() -> OutputReadScope {
        OutputReadScope {
            job_id: JobId::new("job-1").unwrap(),
            agent_id: None,
            stream: None,
        }
    }
    fn wrap(value: &str) -> String {
        format!("op1.{}", URL_SAFE_NO_PAD.encode(value))
    }

    #[test]
    fn output_cursor_roundtrip_keeps_i64_precision_and_exact_filter_scope() {
        let s = scope();
        let c = OutputReadCursor::new(
            s.clone(),
            [7; 32],
            i64::MAX,
            9_007_199_254_740_993,
            4,
            Some(i64::MAX),
        )
        .unwrap();
        let encoded = encode_cursor(&c).unwrap();
        assert!(!encoded.contains('='));
        assert!(encoded.starts_with("op1."));
        assert_eq!(decode_cursor(&s, &encoded).unwrap(), c);
        for other in [
            OutputReadScope {
                agent_id: Some(AgentId::new("a").unwrap()),
                ..s.clone()
            },
            OutputReadScope {
                job_id: JobId::new("job-2").unwrap(),
                ..s.clone()
            },
            OutputReadScope {
                stream: Some(crate::JobOutputStream::Stderr),
                ..s.clone()
            },
        ] {
            assert_eq!(
                decode_cursor(&other, &encoded),
                Err(OutputReadError::ScopeMismatch)
            );
        }
    }

    #[test]
    fn output_cursor_rejects_unknown_duplicate_missing_types_noncanonical_and_oversize() {
        let s = scope();
        let c = OutputReadCursor::new(s.clone(), [7; 32], 0, 0, 0, None).unwrap();
        let encoded = encode_cursor(&c).unwrap();
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.strip_prefix("op1.").unwrap())
            .unwrap();
        let valid: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        let mut bad = Vec::new();
        let mut v = valid.clone();
        v["unknown"] = true.into();
        bad.push(v.to_string());
        for key in ["s", "e", "g", "r", "o", "f"] {
            let mut v = valid.clone();
            v.as_object_mut().unwrap().remove(key);
            bad.push(v.to_string());
        }
        for value in [
            serde_json::json!(1),
            serde_json::json!("-1"),
            serde_json::json!("00"),
            serde_json::json!("+1"),
            serde_json::json!("9223372036854775808"),
        ] {
            let mut v = valid.clone();
            v["g"] = value;
            bad.push(v.to_string());
        }
        for value in [
            serde_json::json!(0),
            serde_json::json!("-1"),
            serde_json::json!({}),
        ] {
            let mut v = valid.clone();
            v["f"] = value;
            bad.push(v.to_string());
        }
        bad.push(format!(
            "{{\"g\":\"0\",{}",
            String::from_utf8(decoded).unwrap().trim_start_matches('{')
        ));
        bad.push(" ".repeat(2049));
        bad.push("{\"s\":\"한글\"}".into());
        for raw in bad {
            assert!(decode_cursor(&s, &wrap(&raw)).is_err());
        }
        for text in [
            format!("{encoded}="),
            encoded.replacen("op1.", "op2.", 1),
            "op1.!".into(),
            "".into(),
        ] {
            assert!(decode_cursor(&s, &text).is_err());
        }
    }

    #[test]
    fn output_query_keeps_path_plus_and_percent_encoded_filters_and_rejects_bad_keys() {
        let request = parse_request(
            "/api/jobs/job%2B1/output-page?limit=1&max_bytes=4096&agent_id=a%2Bb&stream=stderr",
        )
        .unwrap();
        assert_eq!(request.scope.job_id.as_str(), "job+1");
        assert_eq!(request.scope.agent_id.unwrap().as_str(), "a+b");
        assert_eq!(request.scope.stream, Some(crate::JobOutputStream::Stderr));
        assert_eq!(
            (request.limits.fragments(), request.limits.source_bytes()),
            (1, 4096)
        );
        assert!(request.after.is_none());
        for query in [
            "limit=0",
            "limit=257",
            "limit=+1",
            "limit=1.0",
            "limit=18446744073709551616",
            "max_bytes=4095",
            "max_bytes=262145",
            "limit=1&limit=2",
            "other=1",
            "agent_id=",
            "stream=",
            "stream=other",
            "%6cimit=1&limit=2",
            "agent_id=%ff",
            "agent_id=%xy",
            "after=",
            "actor=owner",
            "limit=1&",
        ] {
            assert!(
                parse_request(&format!("/api/jobs/job-1/output-page?{query}")).is_err(),
                "{query}"
            );
        }
        let defaults = parse_request("/api/jobs/job-1/output-page").unwrap();
        assert_eq!(defaults.limits, OutputReadLimits::default());
    }

    #[test]
    fn output_page_route_is_additive_authenticated_and_does_not_infer_empty_job_success() {
        let store = fleet_store::SqliteStore::in_memory().unwrap();
        store
            .insert_admin_token_hash_with_identity(
                &crate::hash_token("viewer-token"),
                "viewer",
                "viewer",
            )
            .unwrap();
        store
            .save_job_record(&Job::new(
                JobId::new("job-1").unwrap(),
                TaskRisk::Low,
                ApprovalRequirement::NotRequired,
                Duration::from_secs(30),
            ))
            .unwrap();
        let get = |path: &str, auth: bool| {
            crate::route_request(
                &format!(
                    "GET {path} HTTP/1.1\r\n{}\r\n",
                    if auth {
                        "Authorization: Bearer viewer-token\r\n"
                    } else {
                        ""
                    }
                ),
                &store,
            )
            .unwrap()
        };
        let unauthorized = get("/api/jobs/job-1/output-page", false);
        assert!(unauthorized.starts_with("HTTP/1.1 401"));
        let response = get("/api/jobs/job-1/output-page", true);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected additive page endpoint"
        );
        assert!(response.contains("Cache-Control: no-store\r\n"));
        let body: serde_json::Value =
            serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body["items"], serde_json::json!([]));
        assert_eq!(body["job_status"], "draft");
        assert_eq!(body["history"], "tracked");
        assert_eq!(body["caught_up"], true);
        let old = get("/api/jobs/job-1/output", true);
        assert_eq!(old.split_once("\r\n\r\n").unwrap().1, "[]\n");
        assert!(get("/api/jobs/missing/output-page", true).starts_with("HTTP/1.1 404"));
        assert_eq!(
            crate::required_permission_for_route("GET", "/api/jobs/job-1/output-page"),
            Some(crate::AdminPermission::JobRead)
        );
    }

    fn output_fixture() -> fleet_store::SqliteStore {
        use fleet_domain::{Agent, AgentFingerprint, AgentIdentity, AgentName, AgentPublicKey};
        let store = fleet_store::SqliteStore::in_memory().unwrap();
        store
            .insert_admin_token_hash(&crate::hash_token("test-token"))
            .unwrap();
        store
            .save_job_record(&Job::new(
                JobId::new("job-1").unwrap(),
                TaskRisk::Low,
                ApprovalRequirement::NotRequired,
                Duration::from_secs(30),
            ))
            .unwrap();
        store
            .save_agent(Agent::new(
                AgentId::new("agent-a").unwrap(),
                AgentName::new("agent-a").unwrap(),
                AgentIdentity {
                    public_key: AgentPublicKey::new("public").unwrap(),
                    fingerprint: AgentFingerprint::new("123456789abcdef0").unwrap(),
                },
            ))
            .unwrap();
        store
    }
    fn get(store: &fleet_store::SqliteStore, path: &str) -> String {
        crate::route_request(
            &format!("GET {path} HTTP/1.1\r\nAuthorization: Bearer test-token\r\n\r\n"),
            store,
        )
        .unwrap()
    }
    fn body(response: &str) -> serde_json::Value {
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
    }

    #[test]
    fn output_page_http_preserves_unicode_decimal_ids_and_bounded_serialized_bytes() {
        let store = output_fixture();
        let original = "\0한🤖\n\"\\".repeat(2000);
        store
            .append_job_output_chunk_record(&crate::JobOutputChunk {
                job_id: "job-1".into(),
                agent_id: "agent-a".into(),
                stream: JobOutputStream::Stdout,
                sequence: 9_007_199_254_740_993,
                body: original.clone(),
            })
            .unwrap();
        let mut after = String::new();
        let mut rebuilt = String::new();
        let mut done = false;
        for _ in 0..30 {
            let response = get(
                &store,
                &format!("/api/jobs/job-1/output-page?max_bytes=4096&limit=1{after}"),
            );
            assert!(response.starts_with("HTTP/1.1 200"));
            assert!(response.contains("Cache-Control: no-store\r\n"));
            assert!(response.split_once("\r\n\r\n").unwrap().1.len() <= 2 * 1024 * 1024);
            let page = body(&response);
            let fragment = &page["items"][0];
            assert_eq!(fragment["sequence"], "9007199254740993");
            assert_eq!(fragment["offset_bytes"], rebuilt.len().to_string());
            assert_eq!(fragment["total_bytes"], original.len().to_string());
            let data = fragment["data"].as_str().unwrap();
            assert!(data.len() + 7 + 6 <= 4096);
            rebuilt.push_str(data);
            after = format!("&after={}", page["next_after"].as_str().unwrap());
            if page["caught_up"] == true {
                done = true;
                break;
            }
        }
        assert!(done);
        assert_eq!(rebuilt, original);
    }

    #[test]
    fn output_page_http_reports_stale_on_retention_and_restore_without_mixing_contexts() {
        let mut store = output_fixture();
        store
            .append_job_output_chunk_record(&crate::JobOutputChunk {
                job_id: "job-1".into(),
                agent_id: "agent-a".into(),
                stream: JobOutputStream::Stdout,
                sequence: 0,
                body: "stored".into(),
            })
            .unwrap();
        let first = body(&get(&store, "/api/jobs/job-1/output-page"));
        let cursor = first["next_after"].as_str().unwrap();
        store
            .cleanup_retention(std::time::SystemTime::now() + Duration::from_secs(1), false)
            .unwrap();
        let stale = get(
            &store,
            &format!("/api/jobs/job-1/output-page?after={cursor}"),
        );
        assert!(stale.starts_with("HTTP/1.1 409"));
        assert_eq!(body(&stale)["error"], "output_cursor_stale");
        let fresh = body(&get(&store, "/api/jobs/job-1/output-page"));
        assert_eq!(fresh["history"], "pruned");
        fleet_application::RotateControllerStoreEpoch::execute(&mut store).unwrap();
        let after_restore = get(
            &store,
            &format!(
                "/api/jobs/job-1/output-page?after={}",
                fresh["next_after"].as_str().unwrap()
            ),
        );
        assert!(after_restore.starts_with("HTTP/1.1 409"));
    }

    #[test]
    fn output_page_errors_are_explicit_uncached_and_do_not_contain_raw_metadata() {
        for (error, status, code) in [
            (OutputReadError::InvalidCursor, 400, "invalid_output_cursor"),
            (OutputReadError::StaleCursor, 409, "output_cursor_stale"),
            (OutputReadError::JobNotFound, 404, "not_found"),
            (
                OutputReadError::MetadataTooLarge,
                413,
                "output_metadata_too_large",
            ),
            (OutputReadError::Unavailable, 500, "output_read_unavailable"),
        ] {
            let response = error_reply(error);
            assert!(response.starts_with(&format!("HTTP/1.1 {status}")));
            assert!(response.contains("Cache-Control: no-store\r\n"));
            assert_eq!(body(&response), serde_json::json!({"error":code}));
        }
        let store = output_fixture();
        for query in [
            "actor=spoof",
            "limit=0",
            "agent_id=",
            "after=op2.x",
            "limit=1&limit=2",
        ] {
            assert!(
                get(&store, &format!("/api/jobs/job-1/output-page?{query}"))
                    .starts_with("HTTP/1.1 400")
            );
        }
        let unauthorized = crate::route_request(
            "GET /api/jobs/job-1/output-page?actor=private HTTP/1.1\r\n\r\n",
            &store,
        )
        .unwrap();
        assert!(unauthorized.starts_with("HTTP/1.1 401"));
        assert!(unauthorized.contains("Cache-Control: no-store\r\n"));
        // Every currently supported role has JobRead. Preserve that policy rather
        // than inventing a restricted role solely to manufacture an HTTP 403.
        for role in [
            crate::AdminRole::Owner,
            crate::AdminRole::Admin,
            crate::AdminRole::Operator,
            crate::AdminRole::Viewer,
        ] {
            assert!(role.allows(crate::AdminPermission::JobRead));
        }
        let forbidden = no_store(crate::forbidden_response(crate::AdminPermission::JobRead));
        assert!(forbidden.starts_with("HTTP/1.1 403"));
        assert!(forbidden.contains("Cache-Control: no-store\r\n"));
    }

    #[test]
    fn output_page_http_rejects_oversized_metadata_without_skipping_the_entry() {
        use fleet_domain::{Agent, AgentFingerprint, AgentIdentity, AgentName, AgentPublicKey};
        let store = output_fixture();
        let id = "z".repeat(4096);
        store
            .save_agent(Agent::new(
                AgentId::new(&id).unwrap(),
                AgentName::new("large-id").unwrap(),
                AgentIdentity {
                    public_key: AgentPublicKey::new("public-large").unwrap(),
                    fingerprint: AgentFingerprint::new("abcdef0123456789").unwrap(),
                },
            ))
            .unwrap();
        store
            .append_job_output_chunk_record(&crate::JobOutputChunk {
                job_id: "job-1".into(),
                agent_id: id,
                stream: JobOutputStream::Stdout,
                sequence: 0,
                body: "x".into(),
            })
            .unwrap();
        let response = get(&store, "/api/jobs/job-1/output-page?max_bytes=4096");
        assert!(response.starts_with("HTTP/1.1 413 Content Too Large"));
        assert_eq!(body(&response)["error"], "output_metadata_too_large");
    }

    #[test]
    fn output_page_wire_budget_includes_json_escaping_and_fails_closed_above_two_mib() {
        use fleet_application::output_read::{OutputFragment, OutputFragmentPosition};
        let store = output_fixture();
        let original = "\0".repeat(262_000);
        store
            .append_job_output_chunk_record(&crate::JobOutputChunk {
                job_id: "job-1".into(),
                agent_id: "agent-a".into(),
                stream: JobOutputStream::Stdout,
                sequence: 0,
                body: original.clone(),
            })
            .unwrap();
        let response = get(&store, "/api/jobs/job-1/output-page?max_bytes=262144");
        assert!(response.starts_with("HTTP/1.1 200"));
        let raw = response.split_once("\r\n\r\n").unwrap().1;
        assert!(raw.len() > 1024 * 1024 && raw.len() <= 2 * 1024 * 1024);
        assert_eq!(body(&response)["items"][0]["data"], original);
        // Defensive serializer fuse if an adapter ever violates its source cap.
        let mut page =
            ReadJobOutputPage::execute(&store, &scope(), None, OutputReadLimits::default())
                .unwrap();
        page.items = vec![
            OutputFragment::new(
                OutputFragmentPosition {
                    chunk_key: 1,
                    sequence: 0,
                    offset_bytes: 0,
                    total_bytes: 360_000,
                },
                AgentId::new("agent-a").unwrap(),
                JobOutputStream::Stdout,
                "\0".repeat(360_000),
            )
            .unwrap(),
        ];
        assert_eq!(serialize_page(page), Err(OutputReadError::Unavailable));
    }
}
