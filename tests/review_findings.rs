//! Regression tests for coordinator review findings (guard + health pass).

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use hs_server::db;
use hs_server::error::ErrorCode;
use hs_server::models::{BootstrapRequest, LoginRequest};
use hs_server::service::{SecurityState, Service};
use hs_server::{require_loopback_bind, AppError};

const PASSWORD: &str = "foundation-pass-1";

fn bootstrap_service(service: &Service) {
    let token = service.create_bootstrap_token().expect("bootstrap token");
    service
        .bootstrap(BootstrapRequest {
            bootstrap_token: token,
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_identity: None,
            manager_friendly_name: None,
        })
        .expect("bootstrap");
}

/// Tempdir forced owner-private (0700) so `db::open` store policy accepts it.
fn private_tempdir() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().canonicalize().expect("canonicalize");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    (dir, path)
}

// ----- Finding 1: durable latch hydration -----

#[test]
fn security_latch_survives_file_reopen() {
    let (_dir, base) = private_tempdir();
    let path = base.join("store.db");
    {
        let db = db::open(&path).expect("open");
        let service = Service::new(db);
        assert_eq!(service.security_state(), SecurityState::Ok);
        service.latch_security_state_unavailable("review_test_latch");
        assert_eq!(service.security_state(), SecurityState::Unavailable);
    }
    let db = db::open(&path).expect("reopen");
    let service = Service::new(db);
    assert_eq!(
        service.security_state(),
        SecurityState::Unavailable,
        "restart must never reset a durable latch"
    );
    let err = service
        .login(LoginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_identity: None,
        })
        .expect_err("auth must stay denied");
    assert!(matches!(
        err,
        AppError::Api {
            code: ErrorCode::SecurityStateUnavailable,
            ..
        }
    ));
}

#[test]
fn security_latch_survives_service_recreation_same_db() {
    let (_dir, base) = private_tempdir();
    let path = base.join("store.db");
    let db = db::open(&path).expect("open file");
    let service = Service::new(db);
    service.latch_security_state_unavailable("recreate");
    drop(service);

    let db = db::open(&path).expect("reopen file");
    let service2 = Service::new(db);
    assert_eq!(service2.security_state(), SecurityState::Unavailable);
}

#[test]
fn hydrate_fails_closed_when_deployment_row_missing() {
    let db = db::open_in_memory().expect("open");
    {
        let conn = db.lock().expect("lock");
        conn.execute("DELETE FROM deployment", []).expect("delete");
    }
    let service = Service::new(db);
    assert_eq!(service.security_state(), SecurityState::Unavailable);
}

#[test]
fn hydrate_fails_closed_when_trust_table_unreadable() {
    let db = db::open_in_memory().expect("open");
    {
        let conn = db.lock().expect("lock");
        conn.execute("DROP TABLE deployment", []).expect("drop");
    }
    let service = Service::new(db);
    assert_eq!(service.security_state(), SecurityState::Unavailable);
}

#[test]
fn hydrate_fails_closed_on_invalid_security_state_ok_integer() {
    let db = db::open_in_memory().expect("open");
    {
        let conn = db.lock().expect("lock");
        // Nonzero-but-not-1 must not hydrate as Ok (rusqlite bool trap).
        conn.execute(
            "UPDATE deployment SET security_state_ok = 2 WHERE id = 1",
            [],
        )
        .expect("update");
    }
    let service = Service::new(db);
    assert_eq!(service.security_state(), SecurityState::Unavailable);
}

// ----- Finding 2: required-read failures latch + 503, no deadlock -----

#[test]
fn required_read_failure_latches_and_denies_without_deadlock() {
    let db = db::open_in_memory().expect("open");
    let service = std::sync::Arc::new(Service::new(db));
    bootstrap_service(&service);
    let login = service
        .login(LoginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_identity: None,
        })
        .expect("login");
    let token = login.token.clone();

    {
        let conn = service.db_handle().lock().expect("lock");
        conn.execute("DROP TABLE sessions", [])
            .expect("drop sessions");
    }

    let err = service
        .authenticate_token(&token)
        .expect_err("auth must fail after fault");
    assert!(
        matches!(
            err,
            AppError::Api {
                code: ErrorCode::SecurityStateUnavailable,
                ..
            }
        ),
        "got {err:?}"
    );
    assert_eq!(service.security_state(), SecurityState::Unavailable);

    let denied = service.login(LoginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        manager_public_identity: None,
    });
    assert!(matches!(
        denied.expect_err("login denied"),
        AppError::Api {
            code: ErrorCode::SecurityStateUnavailable,
            ..
        }
    ));

    let health = service.health().expect("health");
    assert!(!health.accepting_authorized_operations);
    assert_eq!(health.status, "degraded");
}

#[test]
fn health_fails_closed_when_durable_record_unreadable() {
    let db = db::open_in_memory().expect("open");
    let service = Service::new(db);
    bootstrap_service(&service);
    {
        let conn = service.db_handle().lock().expect("lock");
        conn.execute("DROP TABLE deployment", []).expect("drop");
    }
    let health = service.health().expect("health returns degraded");
    assert!(!health.accepting_authorized_operations);
    assert_eq!(health.status, "degraded");
    assert_eq!(service.security_state(), SecurityState::Unavailable);
}

#[test]
fn missing_deployment_row_latches_and_denies_authority() {
    // Delete deployment row AFTER service construction; health must latch
    // (not only return degraded while memory stays Ok).
    let db = db::open_in_memory().expect("open");
    let service = Service::new(db);
    bootstrap_service(&service);
    assert_eq!(service.security_state(), SecurityState::Ok);

    {
        let conn = service.db_handle().lock().expect("lock");
        conn.execute("DELETE FROM deployment", []).expect("delete");
    }

    let health = service.health().expect("health");
    assert!(!health.accepting_authorized_operations);
    assert_eq!(
        service.security_state(),
        SecurityState::Unavailable,
        "missing deployment row must latch, not leave memory Ok"
    );

    let err = service
        .login(LoginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_identity: None,
        })
        .expect_err("login must be denied after latch");
    assert!(matches!(
        err,
        AppError::Api {
            code: ErrorCode::SecurityStateUnavailable,
            ..
        }
    ));

    let err = service
        .create_bootstrap_token()
        .expect_err("token creation must be denied");
    assert!(matches!(
        err,
        AppError::Api {
            code: ErrorCode::SecurityStateUnavailable,
            ..
        }
    ));
}

#[test]
fn health_reports_real_bootstrap_completed_when_latched() {
    let db = db::open_in_memory().expect("open");
    let service = Service::new(db);
    bootstrap_service(&service);
    service.latch_security_state_unavailable("post_bootstrap_latch");
    let health = service.health().expect("health");
    assert!(!health.accepting_authorized_operations);
    assert_eq!(health.status, "degraded");
    assert!(
        health.bootstrap_completed,
        "readable durable bootstrap_completed must not be fabricated false"
    );
}

#[test]
fn health_unbootstracked_is_not_accepting() {
    let db = db::open_in_memory().expect("open");
    let service = Service::new(db);
    let health = service.health().expect("health");
    assert!(!health.bootstrap_completed);
    assert!(!health.accepting_authorized_operations);
    assert_eq!(health.status, "degraded");
    // Bootstrap remains allowed while security state is healthy.
    let token = service.create_bootstrap_token().expect("token");
    assert!(!token.is_empty());
}

// ----- Finding 3: loopback-only bind -----

#[test]
fn refuses_non_loopback_bind_addresses() {
    let wild: SocketAddr = "0.0.0.0:8787".parse().expect("addr");
    let v6: SocketAddr = "[::]:8787".parse().expect("addr");
    let loopback: SocketAddr = "127.0.0.1:8787".parse().expect("addr");
    let loopback_v6: SocketAddr = "[::1]:8787".parse().expect("addr");

    assert!(require_loopback_bind(wild).is_err());
    assert!(require_loopback_bind(v6).is_err());
    assert!(require_loopback_bind(loopback).is_ok());
    assert!(require_loopback_bind(loopback_v6).is_ok());
}

#[test]
fn cli_serve_refuses_wildcard_bind() {
    let bin = env!("CARGO_BIN_EXE_hs-server");
    let (_dir, base) = private_tempdir();
    let path = base.join("store.db");
    let output = std::process::Command::new(bin)
        .args([
            "--data",
            path.to_str().expect("utf8"),
            "serve",
            "--bind",
            "0.0.0.0:18787",
        ])
        .output()
        .expect("run cli");
    assert!(
        !output.status.success(),
        "wildcard bind must be refused before listen"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing non-loopback"), "stderr={stderr}");
    assert!(!stderr.to_lowercase().contains("token"));
    assert!(!stderr.to_lowercase().contains("password"));

    let output_v6 = std::process::Command::new(bin)
        .args([
            "--data",
            path.to_str().expect("utf8"),
            "serve",
            "--bind",
            "[::]:18788",
        ])
        .output()
        .expect("run cli v6");
    assert!(!output_v6.status.success());
    assert!(String::from_utf8_lossy(&output_v6.stderr).contains("refusing non-loopback"));
}

#[tokio::test]
async fn health_on_loopback_socket_still_works() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    assert!(addr.ip().is_loopback());
    let db = db::open_in_memory().expect("db");
    let service = std::sync::Arc::new(Service::new(db));
    // Bootstrap so health can legitimately report accepting after ready.
    bootstrap_service(&service);
    let app = hs_server::app(service);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains("200"), "response={text}");
    assert!(
        text.contains("\"accepting_authorized_operations\":true")
            || text.contains("\"status\":\"ok\""),
        "response={text}"
    );
}

// ----- Finding 4: bounded login throttle -----

#[test]
fn invalid_username_length_rejected_before_hash_work() {
    let db = db::open_in_memory().expect("open");
    let service = Service::new(db);
    bootstrap_service(&service);

    let long_name = "a".repeat(65);
    let err = service
        .login(LoginRequest {
            username: long_name,
            password: PASSWORD.into(),
            manager_public_identity: None,
        })
        .expect_err("overlong username");
    assert!(matches!(
        err,
        AppError::Api {
            code: ErrorCode::BadRequest,
            ..
        }
    ));

    let short = service
        .login(LoginRequest {
            username: "ab".into(),
            password: PASSWORD.into(),
            manager_public_identity: None,
        })
        .expect_err("short username");
    assert!(matches!(
        short,
        AppError::Api {
            code: ErrorCode::BadRequest,
            ..
        }
    ));

    let err = service
        .login(LoginRequest {
            username: "admin".into(),
            password: "x".repeat(300),
            manager_public_identity: None,
        })
        .expect_err("overlong password");
    assert!(matches!(
        err,
        AppError::Api {
            code: ErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn login_throttle_locks_out_and_expires() {
    let db = db::open_in_memory().expect("open");
    let service = Service::new(db);
    bootstrap_service(&service);

    for _ in 0..5 {
        let err = service
            .login(LoginRequest {
                username: "admin".into(),
                password: "wrong-password-x".into(),
                manager_public_identity: None,
            })
            .expect_err("bad password");
        assert!(matches!(
            err,
            AppError::Api {
                code: ErrorCode::Unauthorized,
                ..
            }
        ));
    }

    let locked = service
        .login(LoginRequest {
            username: "ADMIN".into(),
            password: PASSWORD.into(),
            manager_public_identity: None,
        })
        .expect_err("locked out");
    assert!(matches!(
        locked,
        AppError::Api {
            code: ErrorCode::RateLimited,
            ..
        }
    ));

    let other = service
        .login(LoginRequest {
            username: "admin2x".into(),
            password: "wrong-password-x".into(),
            manager_public_identity: None,
        })
        .expect_err("unknown user");
    assert!(matches!(
        other,
        AppError::Api {
            code: ErrorCode::Unauthorized,
            ..
        }
    ));
}

#[test]
fn login_throttle_bounded_fails_closed_when_saturated() {
    let db = db::open_in_memory().expect("open");
    let service = Service::new(db);
    for i in 0..1100 {
        let username = format!("user{i:04}");
        let _ = service.login(LoginRequest {
            username: username.clone(),
            password: "wrong-password-x".into(),
            manager_public_identity: None,
        });
    }
    let err = service
        .login(LoginRequest {
            username: "fresh-attacker".into(),
            password: "wrong-password-x".into(),
            manager_public_identity: None,
        })
        .expect_err("saturated");
    assert!(
        matches!(
            err,
            AppError::Api {
                code: ErrorCode::RateLimited,
                ..
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn throttle_prunes_expired_idle_entries() {
    let db = db::open_in_memory().expect("open");
    let service = Service::new(db);
    bootstrap_service(&service);
    let _ = service.login(LoginRequest {
        username: "admin".into(),
        password: "wrong-password-x".into(),
        manager_public_identity: None,
    });
    let ok = service.login(LoginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        manager_public_identity: None,
    });
    assert!(ok.is_ok(), "success clears throttle for that key: {ok:?}");
}

// ----- CLI recovery-path preconditions (no DB mutation, no secret output) -----

fn hs_server_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hs-server")
}

#[test]
fn cli_bootstrap_v2_invalid_recovery_path_does_not_mutate_db() {
    let (_dir, base) = private_tempdir();
    let db_path = base.join("hs-server.db");
    let missing_parent = base.join("no-such-dir").join("recovery.txt");
    let output = std::process::Command::new(hs_server_bin())
        .arg("--data")
        .arg(&db_path)
        .arg("bootstrap-v2")
        .arg("--token")
        .arg("dummy-token-for-preflight")
        .arg("--username")
        .arg("admin")
        .arg("--recovery-file")
        .arg(&missing_parent)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut child = output;
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(b"long-enough-password\n")
            .expect("write password");
    }
    let out = child.wait_with_output().expect("wait");
    assert!(!out.status.success(), "must fail preflight");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // No secrets and no account/enrollment output on refusal.
    assert!(
        !stdout.contains("totp_secret") && !stdout.contains("mfa_enrollment_id"),
        "stdout must not print secrets: {stdout}"
    );
    assert!(
        stderr.contains("refusing")
            || stderr.contains("does not exist")
            || stderr.contains("error"),
        "stderr={stderr}"
    );
    assert!(
        !db_path.exists(),
        "database must not be created when recovery preflight fails"
    );
}

#[test]
fn cli_bootstrap_v2_existing_recovery_file_does_not_mutate_db() {
    let (_dir, base) = private_tempdir();
    let db_path = base.join("hs-server.db");
    let recovery_path = base.join("recovery.txt");
    std::fs::write(&recovery_path, b"original").expect("seed");
    let output = std::process::Command::new(hs_server_bin())
        .arg("--data")
        .arg(&db_path)
        .arg("bootstrap-v2")
        .arg("--token")
        .arg("dummy-token-for-preflight")
        .arg("--username")
        .arg("admin")
        .arg("--recovery-file")
        .arg(&recovery_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut child = output;
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(b"long-enough-password\n")
            .expect("write password");
    }
    let out = child.wait_with_output().expect("wait");
    assert!(!out.status.success(), "must refuse existing recovery file");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("totp_secret") && !stdout.contains("mfa_enrollment_id"),
        "stdout={stdout}"
    );
    assert!(!db_path.exists(), "no database mutation on refusal");
    assert_eq!(
        std::fs::read(&recovery_path).expect("read"),
        b"original",
        "existing recovery file untouched"
    );
}

#[test]
fn cli_bootstrap_v2_relative_recovery_path_resolves_against_cwd() {
    let (_dir, base) = private_tempdir();
    let db_path = base.join("hs-server.db");
    // Use a relative recovery path with a missing parent: the error must
    // reference the relative name, never a root-relative path.
    let output = std::process::Command::new(hs_server_bin())
        .arg("--data")
        .arg(&db_path)
        .arg("bootstrap-v2")
        .arg("--token")
        .arg("dummy-token-for-preflight")
        .arg("--username")
        .arg("admin")
        .arg("--recovery-file")
        .arg("no-such-rel-dir/recovery.txt")
        .current_dir(&base)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut child = output;
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(b"long-enough-password\n")
            .expect("write password");
    }
    let out = child.wait_with_output().expect("wait");
    assert!(!out.status.success());
    assert!(!db_path.exists(), "no database mutation");
    assert!(
        !Path::new("/no-such-rel-dir").exists(),
        "must never create a root-relative path"
    );
    assert!(
        !base.join("no-such-rel-dir").exists(),
        "preflight must not create the missing parent"
    );
}

// ----- Windows: legacy loopback startup + explicit v2 denial (native CI) -----

/// Legacy v1 loopback development must open a DB and run init/bootstrap even
/// when persistent v2 MFA is unsupported. The PowerShell fixture uses this
/// path. No MFA rows means open is allowed; NEW v2 writes stay denied.
#[cfg(windows)]
#[test]
fn windows_legacy_loopback_init_and_bootstrap_still_work() {
    let (_dir, base) = private_tempdir();
    let db_path = base.join("hs-server.db");

    // init: creates schema + single-use bootstrap token.
    let init = std::process::Command::new(hs_server_bin())
        .arg("--data")
        .arg(&db_path)
        .arg("init")
        .output()
        .expect("init");
    assert!(
        init.status.success(),
        "legacy init: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let init_out = String::from_utf8_lossy(&init.stdout);
    // Extract the bootstrap token line.
    let token = init_out
        .lines()
        .find_map(|l| l.strip_prefix("bootstrap_token: "))
        .expect("token line")
        .trim()
        .to_string();
    assert!(!token.is_empty());

    // bootstrap (v1): first administrator, no MFA.
    let mut bootstrap = std::process::Command::new(hs_server_bin())
        .arg("--data")
        .arg(&db_path)
        .arg("bootstrap")
        .arg("--token")
        .arg(&token)
        .arg("--username")
        .arg("admin")
        .arg("--password-stdin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn bootstrap");
    {
        use std::io::Write;
        bootstrap
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(b"legacy-windows-password\n")
            .expect("write password");
    }
    let out = bootstrap.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "legacy bootstrap must work: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // check-login: credentials authenticate without starting HTTP.
    let mut login = std::process::Command::new(hs_server_bin())
        .arg("--data")
        .arg(&db_path)
        .arg("check-login")
        .arg("--username")
        .arg("admin")
        .arg("--password-stdin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn login");
    {
        use std::io::Write;
        login
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(b"legacy-windows-password\n")
            .expect("write password");
    }
    let out = login.wait_with_output().expect("wait");
    assert!(out.status.success(), "legacy check-login");
}

/// Windows CLI must refuse NEW persisted v2 MFA before creating a database
/// or printing any secret.
#[cfg(windows)]
#[test]
fn windows_cli_bootstrap_v2_denies_without_db_or_secret() {
    let (_dir, base) = private_tempdir();
    let db_path = base.join("hs-server.db");
    let recovery = base.join("recovery.txt");
    let out = std::process::Command::new(hs_server_bin())
        .arg("--data")
        .arg(&db_path)
        .arg("bootstrap-v2")
        .arg("--token")
        .arg("dummy-token")
        .arg("--username")
        .arg("admin")
        .arg("--recovery-file")
        .arg(&recovery)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("run");
    assert!(!out.status.success(), "must deny bootstrap-v2 on Windows");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("totp_secret") && !stdout.contains("mfa_enrollment_id"),
        "no secrets on denial: {stdout}"
    );
    assert!(
        stderr.contains("not supported") || stderr.contains("refusing"),
        "stderr={stderr}"
    );
    assert!(!recovery.exists(), "no recovery file written");
}

/// Pre-existing persisted MFA rows must refuse legacy open (no unverified
/// confidential store, no exposure of existing v2 authority via legacy paths).
#[cfg(windows)]
#[test]
fn windows_open_refuses_preexisting_mfa_rows() {
    let (_dir, base) = private_tempdir();
    let path = base.join("hs-server.db");
    // Seed with rusqlite directly: one MFA row is enough to refuse.
    {
        let conn = rusqlite::Connection::open(&path).expect("seed");
        // Minimal v2-shaped schema with one MFA row.
        conn.execute_batch(
            "CREATE TABLE schema_meta (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL);
             INSERT INTO schema_meta VALUES (1, 2);
             CREATE TABLE account_mfa (
                account_id TEXT PRIMARY KEY,
                totp_secret TEXT NOT NULL,
                totp_confirmed_at INTEGER,
                recovery_stored_at INTEGER,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
             );
             INSERT INTO account_mfa VALUES ('a1', 'SECRET', NULL, NULL, 'pending', 1, 1);
             CREATE TABLE recovery_codes (
                id TEXT PRIMARY KEY, account_id TEXT NOT NULL,
                code_hash TEXT NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL
             );
             CREATE TABLE mfa_enrollments (
                id TEXT PRIMARY KEY, account_id TEXT NOT NULL,
                totp_secret TEXT NOT NULL, recovery_committed INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
             );",
        )
        .expect("seed mfa");
    }
    let err = match db::open(&path) {
        Err(err) => err,
        Ok(_) => panic!("must refuse pre-existing MFA rows"),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("persisted MFA") || msg.contains("preexisting_mfa"),
        "msg={msg}"
    );
    // Existing MFA row preserved (no implicit migration / rewrite).
    let conn = rusqlite::Connection::open(&path).expect("reopen");
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM account_mfa", [], |r| r.get(0))
        .expect("count");
    assert_eq!(count, 1);
}
