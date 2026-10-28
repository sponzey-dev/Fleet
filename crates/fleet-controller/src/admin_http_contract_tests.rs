//! Header/origin and finite admission contracts; fake time never changes process settings.

use super::*;

#[test]
fn canonical_origin_is_bootstrap_only_and_https_cookies_are_host_bound() {
    for raw in [
        None,
        Some("https://*.invalid"),
        Some("https://user:password@fleet.invalid"),
        Some("https://fleet.invalid?query"),
        Some("https://fleet.invalid/#fragment"),
        Some("https://fleet.invalid/path"),
        Some("http://0.0.0.0:7700"),
        Some("http://[::]:7700"),
        Some("file:///fleet"),
    ] {
        assert!(matches!(
            CookiePolicy::parse(raw),
            Err(AdminAccessError::Unavailable)
        ));
    }
    let policy = CookiePolicy::parse(Some("https://FLEET.invalid:443/")).unwrap();
    assert_eq!(policy.origin, "https://fleet.invalid");
    let cookie = policy.cookie("fixture", 28800);
    assert!(cookie.starts_with("__Host-fleet_session="));
    for flag in [
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Max-Age=28800",
    ] {
        assert!(cookie.contains(flag));
    }
    assert!(!cookie.contains("Domain="));
    let good=RequestHeaders::parse("POST /api/auth/login HTTP/1.1\r\nHost: attacker.invalid\r\nOrigin: https://fleet.invalid\r\n\r\n").unwrap();
    assert!(policy.require_origin(&good).is_ok());
    let spoof=RequestHeaders::parse("POST /api/auth/login HTTP/1.1\r\nHost: fleet.invalid\r\nX-Forwarded-Host: fleet.invalid\r\nOrigin: https://attacker.invalid\r\n\r\n").unwrap();
    assert!(policy.require_origin(&spoof).is_err());
}

#[test]
fn credentials_are_unique_header_scoped_and_never_sourced_from_the_body() {
    let policy = CookiePolicy::parse(Some("http://127.0.0.1:7700")).unwrap();
    let body=RequestHeaders::parse("GET /api/agents HTTP/1.1\r\n\r\nAuthorization: Bearer body\r\nCookie: fleet_session=body\r\n").unwrap();
    assert!(body.credential(&policy).unwrap().is_none());
    for head in [
        "Cookie: fleet_session=a; fleet_session=b",
        "Cookie: fleet_session=a; __Host-fleet_session=b",
        "Cookie: fleet_session=a\r\nAuthorization: Bearer b",
        "Authorization: Bearer a\r\nauthorization: Bearer b",
    ] {
        let request = format!("GET /api/agents HTTP/1.1\r\n{head}\r\n\r\n");
        assert!(matches!(
            RequestHeaders::parse(&request).unwrap().credential(&policy),
            Err((400, "ambiguous_authentication"))
        ));
    }
    let request = "GET /api/agents HTTP/1.1\r\nCookie: __Host-fleet_session=wrong-name\r\n\r\n";
    assert!(matches!(
        RequestHeaders::parse(request).unwrap().credential(&policy),
        Err((401, "unauthorized"))
    ));
}

#[test]
fn login_failures_and_in_flight_attempts_share_five_attempts_per_canonical_name() {
    let limiter = Arc::new(Mutex::new(FailureLimiter::default()));
    let start = Instant::now();
    let mut live = Vec::new();
    for _ in 0..5 {
        live.push(FailureLimiter::reserve_at(&limiter, "FiXtUrE", start).unwrap());
    }
    assert!(matches!(
        FailureLimiter::reserve_at(&limiter, "fixture", start),
        Err((429, _))
    ));
    for attempt in live {
        attempt.failed();
    }
    assert!(matches!(
        FailureLimiter::reserve_at(&limiter, "fixture", start + Duration::from_secs(299)),
        Err((429, _))
    ));
    assert!(
        FailureLimiter::reserve_at(&limiter, "fixture", start + Duration::from_secs(300)).is_ok()
    );
    assert_eq!(limiter.lock().unwrap().entries.len(), 1);
}

#[test]
fn limiter_keys_are_bounded_and_expire_without_a_periodic_worker() {
    let limiter = Arc::new(Mutex::new(FailureLimiter::default()));
    let start = Instant::now();
    for n in 0..512 {
        drop(FailureLimiter::reserve_at(&limiter, &format!("fixture_{n}"), start).unwrap());
    }
    assert!(matches!(
        FailureLimiter::reserve_at(&limiter, "another", start),
        Err((429, _))
    ));
    assert_eq!(limiter.lock().unwrap().entries.len(), 512);
    assert!(
        FailureLimiter::reserve_at(&limiter, "another", start + Duration::from_secs(300)).is_ok()
    );
    assert_eq!(limiter.lock().unwrap().entries.len(), 1);
}

#[test]
fn legacy_bearer_extraction_also_rejects_body_and_duplicate_authorization() {
    let store = SqliteStore::in_memory().unwrap();
    store
        .insert_admin_token_hash(&hash_token("fixture-bearer"))
        .unwrap();
    assert!(
        crate::route_request(
            "GET /api/agents HTTP/1.1\r\nAuthorization: Bearer fixture-bearer\r\n\r\n",
            &store
        )
        .unwrap()
        .starts_with("HTTP/1.1 200")
    );
    for request in [
        "GET /api/agents HTTP/1.1\r\n\r\nAuthorization: Bearer fixture-bearer",
        "GET /api/agents HTTP/1.1\r\nAuthorization: Bearer fixture-bearer\r\nauthorization: Bearer other\r\n\r\n",
    ] {
        assert!(
            crate::route_request(request, &store)
                .unwrap()
                .starts_with("HTTP/1.1 401")
        );
    }
}

#[test]
fn legacy_http_also_rejects_known_session_cookie_and_bearer_ambiguity() {
    let root = tempfile::tempdir().unwrap();
    let store = SqliteStore::in_memory().unwrap();
    store
        .insert_admin_token_hash(&hash_token("fixture-bearer"))
        .unwrap();
    let state = ControllerAppState {
        store: Arc::new(Mutex::new(ControllerStore::Sqlite(store))),
        artifact_store: Arc::new(Mutex::new(
            LocalArtifactStore::new(root.path().join("artifacts")).unwrap(),
        )),
        identity: Arc::new(ControllerIdentity::dev_insecure()),
        metadata: Arc::new(ControllerRuntimeMetadata::default()),
        sessions: Arc::new(Mutex::new(AgentSessionRegistry::default())),
        catalog_sync_submitter: None,
        admin_auth: None,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    for (cookie, expected) in [
        ("unrelated=value", 200),
        ("fleet_session=untrusted", 400),
        ("__Host-fleet_session=untrusted", 400),
    ] {
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/api/agents")
            .header("Authorization", "Bearer fixture-bearer")
            .header("Cookie", cookie)
            .body(axum::body::Body::empty())
            .unwrap();
        let response = runtime.block_on(crate::axum_http_fallback(State(state.clone()), request));
        assert_eq!(
            response.status(),
            expected,
            "legacy mode must not choose an actor from ambiguous input"
        );
    }
}
