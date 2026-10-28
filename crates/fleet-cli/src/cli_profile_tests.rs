//! Private synthetic profile and loopback boundaries; no user credentials or servers.
use super::*;

#[test]
fn personal_login_defaults_to_hidden_input_and_accepts_explicit_stdin() {
    for extra in [None, Some("--token-stdin")] {
        let mut args = vec![
            "fleet",
            "login",
            "--controller-url",
            "https://fleet.example.com",
        ];
        if let Some(flag) = extra {
            args.push(flag);
        }
        assert!(Cli::try_parse_from(args).is_ok());
    }
}

#[test]
fn personal_profile_login_can_select_a_private_ca_without_global_trust_changes() {
    assert!(
        Cli::try_parse_from([
            "fleet",
            "login",
            "--controller-url",
            "https://localhost:35433",
            "--tls-ca-cert",
            "/private/test-ca.pem",
            "--token-stdin"
        ])
        .is_ok()
    );
}

#[test]
fn profile_token_cannot_follow_a_different_server_override() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile.json");
    save_cli_profile(
        &path,
        &CliProfile {
            controller_url: "https://fleet.example.com".into(),
            admin_token: "synthetic-profile-secret".into(),
            tls_ca_cert: None,
        },
    )
    .unwrap();
    let result = resolve_protected_api(&ProtectedApiArgs {
        controller_url: Some("https://other.example.com".into()),
        admin_token: None,
        profile_path: path,
    });
    assert!(
        result.is_err(),
        "a saved credential must remain scoped to its server"
    );
    let same = resolve_protected_api(&ProtectedApiArgs {
        controller_url: Some("https://FLEET.example.com:443/".into()),
        admin_token: None,
        profile_path: dir.path().join("profile.json"),
    })
    .unwrap();
    assert_eq!(same.controller_url, "https://fleet.example.com");
}

#[cfg(unix)]
#[test]
fn unsafe_existing_profile_is_never_repaired_or_overwritten_and_new_directory_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private").join("profile.json");
    let profile = CliProfile {
        controller_url: "https://fleet.example.com".into(),
        admin_token: "synthetic-profile-secret".into(),
        tls_ca_cert: None,
    };
    save_cli_profile(&path, &profile).unwrap();
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let original = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(save_cli_profile(&path, &profile).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&path, dir.path().join("alias.json")).unwrap();
    assert!(read_cli_profile(&path).is_err());
    assert!(save_cli_profile(&path, &profile).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn malformed_profile_diagnostics_and_debug_do_not_echo_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile.json");
    fs::write(&path, r#"{"controller_url":"https://fleet.example.com","admin_token":false,"synthetic-secret":"x"}"#).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let error = read_cli_profile(&path).unwrap_err().to_string();
    assert!(!error.contains("false"));
    let profile = CliProfile {
        controller_url: "https://fleet.example.com".into(),
        admin_token: "synthetic-profile-secret".into(),
        tls_ca_cert: None,
    };
    assert!(!format!("{profile:?}").contains("synthetic-profile-secret"));
}

#[cfg(unix)]
#[test]
fn profile_rejects_symlink_without_modifying_its_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.json");
    let link = dir.path().join("profile.json");
    fs::write(&target, "preserve target").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let profile = CliProfile {
        controller_url: "https://fleet.example.com".into(),
        admin_token: "synthetic-profile-secret".into(),
        tls_ca_cert: None,
    };
    assert!(read_cli_profile(&link).is_err());
    assert!(save_cli_profile(&link, &profile).is_err());
    assert_eq!(fs::read_to_string(target).unwrap(), "preserve target");
}

#[test]
fn protected_token_request_does_not_follow_redirects() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut count = 0;
        while Instant::now() < deadline && count < 2 {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut bytes = [0; 4096];
                    let received = socket.read(&mut bytes).unwrap();
                    assert!(received > 0);
                    count += 1;
                    let response = if count == 1 {
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: http://{address}/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".into()
                    };
                    socket.write_all(response.as_bytes()).unwrap();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(_) => panic!("owned loopback listener failed"),
            }
        }
        count
    });
    let client = ProtectedApiClient {
        controller_url: format!("http://{address}"),
        admin_token: "synthetic-token".into(),
        tls_ca_pem: None,
    };
    let result = client.get("/api/auth/session");
    let count = worker.join().unwrap();
    assert!(result.is_err(), "a redirect must be an explicit failure");
    assert_eq!(count, 1, "do not replay the bearer request at a redirect");
}

#[test]
fn credential_rejection_explains_expiry_revocation_without_claiming_job_failure() {
    let message = render_http_status_error(401);
    assert!(message.contains("expired") && message.contains("revoked"));
    assert!(!message.contains("job failed"));
    assert!(!render_http_status_error(403).contains("sign in"));
}

#[test]
fn login_refuses_password_or_web_session_in_personal_token_input() {
    for secret in [
        "a password phrase",
        "fws_0123456789",
        "fsetup_0123456789",
        "fpat_short",
    ] {
        assert!(validate_personal_token(secret).is_err());
    }
    assert!(validate_personal_token(&format!("fpat_{}", "a".repeat(64))).is_ok());
}

#[test]
fn private_ca_input_is_bounded_and_never_echoes_certificate_or_key_material() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.pem");
    for body in [
        "private-material-sentinel".to_string(),
        "private-material-sentinel".repeat(1024),
        "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n".to_string(),
    ] {
        fs::write(&path, body).unwrap();
        let error = read_profile_ca(Some(&path)).unwrap_err().to_string();
        assert!(!error.contains("private-material-sentinel"));
    }
    assert!(read_profile_ca(Some(dir.path())).is_err());
    assert!(read_profile_ca(Some(&dir.path().join("missing.pem"))).is_err());
    assert_eq!(read_profile_ca(None).unwrap(), None);
}

#[cfg(unix)]
#[test]
fn private_ca_fifo_is_rejected_without_waiting_for_a_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca-fifo");
    assert!(
        ProcessCommand::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let (send, receive) = mpsc::channel();
    let worker_path = path.clone();
    let worker = thread::spawn(move || {
        send.send(read_profile_ca(Some(&worker_path)).is_err())
            .unwrap()
    });
    let immediate = receive.recv_timeout(Duration::from_secs(1));
    if immediate.is_err() {
        // Release the faulty blocking reader before reporting RED; never leave a test thread behind.
        let _writer = OpenOptions::new()
            .write(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(&path);
        assert!(receive.recv_timeout(Duration::from_secs(2)).unwrap());
    }
    worker.join().unwrap();
    assert_eq!(immediate, Ok(true));
}

#[test]
fn profile_url_is_one_canonical_origin_and_errors_are_redacted() {
    for raw in [
        "https://user:synthetic-secret@fleet.example.com",
        "https://fleet.example.com/path",
        "https://fleet.example.com/?secret=synthetic-secret",
        "https://fleet.example.com/#synthetic-secret",
        "http://0.0.0.0",
        "http://[::]",
        "http://localhost:0",
        "https://fleet.example.com\\evil",
    ] {
        let error = canonical_profile_url(raw).unwrap_err().to_string();
        assert!(!error.contains("synthetic-secret"));
    }
    assert_eq!(
        canonical_profile_url("https://FLEET.example.com:443/").unwrap(),
        "https://fleet.example.com"
    );
}
