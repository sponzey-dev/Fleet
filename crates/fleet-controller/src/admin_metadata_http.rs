//! Strict bounded human-metadata query and scoped position codec. Positions never grant
//! authority; callers validate typed IDs and Application revalidates the current actor.

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataCursor {
    v: u8,
    purpose: String,
    owner: String,
    after: String,
}

pub(super) fn encode_cursor(
    after: &str,
    actor: &AuthenticatedAdmin,
    purpose: &str,
) -> Result<String, HttpFailure> {
    let bytes = serde_json::to_vec(&MetadataCursor {
        v: 1,
        purpose: purpose.to_owned(),
        owner: actor.user_id().as_str().to_owned(),
        after: after.to_owned(),
    })
    .map_err(|_| (503, "authentication_unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) fn decode_cursor(
    value: &str,
    actor: &AuthenticatedAdmin,
    purpose: &str,
) -> Result<String, HttpFailure> {
    if value.is_empty() || value.len() > 512 {
        return Err((400, "invalid_cursor"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| (400, "invalid_cursor"))?;
    let cursor: MetadataCursor =
        serde_json::from_slice(&bytes).map_err(|_| (400, "invalid_cursor"))?;
    if cursor.v != 1 || cursor.purpose != purpose || cursor.owner != actor.user_id().as_str() {
        return Err((400, "invalid_cursor"));
    }
    Ok(cursor.after)
}

fn query_component(value: &str) -> Result<String, HttpFailure> {
    if value.len() > 1536 {
        return Err((400, "invalid_request"));
    }
    let mut output = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let high = bytes
                    .next()
                    .and_then(|value| (value as char).to_digit(16))
                    .ok_or((400, "invalid_request"))?;
                let low = bytes
                    .next()
                    .and_then(|value| (value as char).to_digit(16))
                    .ok_or((400, "invalid_request"))?;
                output.push((high * 16 + low) as u8);
            }
            b'+' => output.push(b' '),
            byte => output.push(byte),
        }
    }
    String::from_utf8(output).map_err(|_| (400, "invalid_request"))
}

pub(super) fn page_query<T>(
    query: Option<&str>,
    decode: impl Fn(&str) -> Result<T, HttpFailure>,
) -> Result<(AdminMetadataPageSize, Option<T>), HttpFailure> {
    let mut limit = AdminMetadataPageSize::default();
    let mut after = None;
    let mut seen = BTreeSet::new();
    if let Some(query) = query {
        if query.is_empty() || query.len() > 4096 {
            return Err((400, "invalid_request"));
        }
        for part in query.split('&') {
            let (name, value) = part.split_once('=').ok_or((400, "invalid_request"))?;
            let name = query_component(name)?;
            if !seen.insert(name.clone()) {
                return Err((400, "invalid_request"));
            }
            let value = query_component(value)?;
            match name.as_str() {
                "limit" => {
                    if value.is_empty()
                        || value.len() > 3
                        || !value.bytes().all(|value| value.is_ascii_digit())
                    {
                        return Err((400, "invalid_request"));
                    }
                    limit = AdminMetadataPageSize::new(
                        value.parse().map_err(|_| (400, "invalid_request"))?,
                    )
                    .map_err(|_| (400, "invalid_request"))?;
                }
                "after" => after = Some(decode(&value)?),
                _ => return Err((400, "invalid_request")),
            }
        }
    }
    Ok((limit, after))
}
