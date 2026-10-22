//! HTTP integration tests for contract v1.
//!
//! Covers deny-before-approval, scoped inventory, invalid session, competing
//! unique claims, single-use bootstrap, and schema initialization refusals.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use hs_server::db;
use hs_server::models::{
    ApproveManagerRequest, BootstrapRequest, CreateComputerRequest, GrantAccessRequest,
    LoginRequest, RegisterManagerRequest,
};
use hs_server::service::Service;

const PASSWORD: &str = "foundation-pass-1";

fn service() -> std::sync::Arc<Service> {
    let db = db::open_in_memory().expect("in-memory db");
    std::sync::Arc::new(Service::new(db))
}

fn app() -> Router {
    hs_server::app(service())
}

#[tokio::test]
async fn network_router_publishes_public_authority_identity_and_generation() {
    let service = service();
    let expected_deployment_id = service.deployment_id().expect("deployment id");
    let expected_public_key = service
        .grant_signing_public_key()
        .expect("grant verification key");
    let expected_authority_generation = service
        .authority_generation()
        .expect("authority generation");
    let response = hs_server::network_app(service)
        .oneshot(
            Request::get("/v2/deployment/authority")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("authority response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("authority body")
        .to_bytes();
    let authority: Value = serde_json::from_slice(&body).expect("authority JSON");
    assert_eq!(authority["deployment_id"], expected_deployment_id);
    assert_eq!(authority["grant_signing_public_key"], expected_public_key);
    assert_eq!(
        authority["authority_generation"],
        expected_authority_generation
    );
    assert!(authority.get("grant_signing_secret").is_none());
    let public_key_bytes = hex::decode(&expected_public_key).expect("hex public key");
    let public_key_bytes: [u8; 32] = public_key_bytes.try_into().expect("32-byte public key");
    ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).expect("valid Ed25519 key");
}

#[tokio::test]
async fn network_router_exposes_v2_and_health_but_not_legacy_v1() {
    let network = hs_server::network_app(service());

    for path in ["/v1/bootstrap", "/v1/auth/login", "/v1/auth/session"] {
        let request = Request::get(path).body(Body::empty()).expect("request");
        let response = network.clone().oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }

    let health = Request::get("/health")
        .body(Body::empty())
        .expect("request");
    let response = network.clone().oneshot(health).await.expect("health");
    assert_eq!(response.status(), StatusCode::OK);
    let health_body = response
        .into_body()
        .collect()
        .await
        .expect("health body")
        .to_bytes();
    let health: Value = serde_json::from_slice(&health_body).expect("health JSON");
    assert_eq!(health["features"]["file_jobs"], true);
    assert_eq!(health["authority_state"], "active");
    assert_eq!(health["authority_generation"], 1);

    let invitation_list = Request::get("/v2/enrollment/invitations")
        .body(Body::empty())
        .expect("request");
    let response = network
        .clone()
        .oneshot(invitation_list)
        .await
        .expect("v2 route");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let cutover_status = Request::get("/v2/authority/cutover")
        .body(Body::empty())
        .expect("cutover status");
    let response = network
        .clone()
        .oneshot(cutover_status)
        .await
        .expect("cutover status route");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    for (method, path) in [
        ("POST", "/v2/admissions/observation"),
        (
            "POST",
            "/v2/endpoints/admissions/observation/redeem",
        ),
        ("GET", "/v2/files/requests"),
        ("POST", "/v2/files/requests"),
        (
            "POST",
            "/v2/files/requests/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/publish",
        ),
        (
            "GET",
            "/v2/files/requests/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/submissions",
        ),
        (
            "DELETE",
            "/v2/files/requests/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/submissions/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc",
        ),
        (
            "GET",
            "/v2/files/requests/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/submissions/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/files/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/chunks/0",
        ),
        ("GET", "/v2/endpoints/file-requests"),
        (
            "GET",
            "/v2/endpoints/file-requests/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/submissions",
        ),
        (
            "POST",
            "/v2/endpoints/file-requests/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/submissions",
        ),
        (
            "PUT",
            "/v2/endpoints/file-requests/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/submissions/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/files/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/chunks/0",
        ),
        (
            "POST",
            "/v2/endpoints/file-requests/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/submissions/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/complete",
        ),
        ("GET", "/v2/files/jobs"),
        ("POST", "/v2/files/jobs"),
        (
            "GET",
            "/v2/files/recipients/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc",
        ),
        ("GET", "/v2/files/jobs/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc"),
        (
            "POST",
            "/v2/files/jobs/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc",
        ),
        (
            "PUT",
            "/v2/files/jobs/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/chunks/0",
        ),
        ("GET", "/v2/endpoints/jobs"),
        (
            "GET",
            "/v2/endpoints/jobs/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/chunks/0",
        ),
        (
            "POST",
            "/v2/endpoints/jobs/7b1c6105-22c1-4212-bc5e-0cd83e89d7dc/result",
        ),
    ] {
        let mut request = Request::builder().method(method).uri(path);
        let body = if method == "POST" || method == "DELETE" {
            let value = if path == "/v2/admissions/observation" {
                json!({"computer_id":"7b1c6105-22c1-4212-bc5e-0cd83e89d7dc"})
            } else if path == "/v2/endpoints/admissions/observation/redeem" {
                json!({
                    "grant_token":"invalid",
                    "endpoint_nonce":"00",
                    "channel_binding":"00",
                    "manager_proof":"00"
                })
            } else if path == "/v2/files/jobs" {
                json!({
                    "file_name":"test.bin",
                    "file_size_bytes":0,
                    "sha256":"00",
                    "computer_ids":["7b1c6105-22c1-4212-bc5e-0cd83e89d7dc"],
                    "expected_recipients":[{
                        "computer_id":"7b1c6105-22c1-4212-bc5e-0cd83e89d7dc",
                        "session_id":"7b1c6105-22c1-4212-bc5e-0cd83e89d7dc"
                    }]
                })
            } else if path == "/v2/files/requests" {
                json!({
                    "title":"Collect logs",
                    "instructions":"Attach the requested log file.",
                    "computer_ids":["7b1c6105-22c1-4212-bc5e-0cd83e89d7dc"],
                    "allowed_extensions":["txt"],
                    "max_file_count":1,
                    "max_total_size_bytes":1024,
                    "closes_at_unix":2_000_000_000_i64,
                    "replacement_allowed":false
                })
            } else if path.ends_with("/publish") {
                json!({"expected_revision":1})
            } else if path.ends_with("/submissions") {
                json!({
                    "request_revision":2,
                    "files":[],
                    "replace_submission_id":null,
                    "confirm_replacement":false
                })
            } else if path.ends_with("/complete") {
                json!({
                    "request_revision":2,
                    "confirm_submission_id":"7b1c6105-22c1-4212-bc5e-0cd83e89d7dc"
                })
            } else if method == "DELETE" {
                json!({"confirm_submission_id":"7b1c6105-22c1-4212-bc5e-0cd83e89d7dc"})
            } else if path.ends_with("/result") {
                json!({"succeeded":false,"detail":"test failure"})
            } else {
                json!({"confirm_job_id":"7b1c6105-22c1-4212-bc5e-0cd83e89d7dc"})
            };
            request = request.header("content-type", "application/json");
            Body::from(value.to_string())
        } else {
            Body::empty()
        };
        let request = request.body(body).expect("file jobs request");
        let response = network.clone().oneshot(request).await.expect("file route");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
    }
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = if let Some(body) = body {
        builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request")
    } else {
        builder.body(Body::empty()).expect("request")
    };
    let response = app.clone().oneshot(request).await.expect("oneshot");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "json body for status {status}: {error}; raw body={:?}",
                String::from_utf8_lossy(&bytes)
            )
        })
    };
    (status, value)
}

async fn send_bytes(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: &[u8],
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .header("content-type", "application/octet-stream")
                .body(Body::from(body.to_vec()))
                .expect("binary request"),
        )
        .await
        .expect("oneshot");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("binary response")
        .to_bytes()
        .to_vec();
    (status, headers, bytes)
}

/// Bootstrap the first administrator (single-use) and return an authenticated
/// context via a historical fixture session. Administrator MFA is mandatory, so
/// a real v1 password login is refused; these tests need a session row, not a
/// legacy administrator bypass.
fn bootstrap_admin(service: &Service) -> hs_server::service::AuthContext {
    let token = service.create_bootstrap_token().expect("bootstrap token");
    let created = service
        .bootstrap(BootstrapRequest {
            bootstrap_token: token,
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_identity: Some("admin-manager".into()),
            manager_friendly_name: Some("Admin manager".into()),
        })
        .expect("bootstrap");
    seed_fixture_session(service, &created.account.id, None)
}

/// Replace the bootstrap session's historical label-only manager with a
/// key-bearing approved manager fixture for v2 administration tests.
fn bootstrap_admin_with_manager_key(
    service: &Service,
) -> (hs_server::service::AuthContext, String) {
    let admin = bootstrap_admin(service);
    let token = format!("fixture-token-{}", admin.account_id);
    {
        let conn = service.db_handle().lock().expect("store");
        let manager_id: String = conn
            .query_row(
                "SELECT id FROM managers WHERE public_identity = 'admin-manager'",
                [],
                |row| row.get(0),
            )
            .expect("bootstrap manager");
        conn.execute(
            "UPDATE managers SET public_key = 'fixture-public-key' WHERE id = ?1",
            rusqlite::params![manager_id],
        )
        .expect("install test-only manager key");
        conn.execute(
            "UPDATE sessions SET manager_id = ?1 WHERE id = ?2",
            rusqlite::params![manager_id, format!("sess-{}", admin.account_id)],
        )
        .expect("bind manager to test session");
    }
    let auth = service
        .authenticate_token(&token)
        .expect("keyed admin auth");
    (auth, token)
}

/// Seed a non-administrator with a known password (test-only). Used where the
/// seam under test is manager binding on v1 login — administrator MFA is
/// mandatory and cannot be exercised through password-only login.
fn seed_non_admin(service: &Service, username: &str, password: &str) {
    let hash = hs_server::crypto::hash_password(password).expect("hash");
    let now = hs_server::crypto::unix_now() as i64;
    let conn = service.db_handle().lock().expect("store");
    conn.execute(
        "INSERT INTO accounts (
            id, username, password_hash, state,
            can_operate, can_manage_enrollment, can_manage_access,
            can_manage_accounts, can_manage_security,
            revision, created_at, updated_at
         ) VALUES (?1, ?2, ?3, 'active', 1, 0, 0, 0, 0, 1, ?4, ?4)",
        rusqlite::params![format!("acct-{username}"), username, hash, now],
    )
    .expect("seed non-admin");
}

/// Insert a historical session fixture (test-only). Never a production path.
fn seed_fixture_session(
    service: &Service,
    account_id: &str,
    manager_id: Option<&str>,
) -> hs_server::service::AuthContext {
    let session_id = format!("sess-{account_id}");
    let token = format!("fixture-token-{account_id}");
    let token_hash = hs_server::crypto::hash_token(&token);
    let now = hs_server::crypto::unix_now() as i64;
    {
        let conn = service.db_handle().lock().expect("store");
        // Historical MFA-assured session row (test-only). Administrator MFA is
        // mandatory at the authority-use boundary; these tests need a genuine
        // MFA-backed session record, not a legacy password bypass.
        conn.execute(
            "INSERT INTO sessions (
                id, account_id, manager_id, token_hash, created_at, expires_at,
                assurance, mfa_assured_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'mfa', ?5)",
            rusqlite::params![
                session_id,
                account_id,
                manager_id,
                token_hash,
                now,
                now + 3600
            ],
        )
        .expect("seed fixture session");
    }
    service.authenticate_token(&token).expect("fixture auth")
}

/// Tempdir whose `base` is store-parent ready: Unix owner-private (0700);
/// Windows a genuine private product child via `ensure_private_store_dir`.
fn private_tempdir() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    #[cfg(windows)]
    let base = {
        let child = dir.path().join("hs-store");
        hs_server::private_file::ensure_private_store_dir(&child)
            .expect("windows private product child");
        child
    };
    #[cfg(not(windows))]
    let base = {
        let path = dir.path().canonicalize().expect("canonicalize");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        path
    };
    (dir, base)
}

#[tokio::test]
async fn health_reports_foundation_features() {
    let app = app();
    // Fresh deployment: bootstrap not completed → degraded, no admission.
    let (status, body) = send(&app, "GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["bootstrap_completed"], false);
    assert_eq!(body["accepting_authorized_operations"], false);
    assert_eq!(body["features"]["local_accounts"], true);
    assert_eq!(body["features"]["mfa"], true);
    assert_eq!(body["features"]["file_jobs"], true);
    assert_eq!(body["features"]["security_recovery"], false);
    assert_eq!(body["features"]["remote_control"], false);
}

#[tokio::test]
async fn health_accepts_only_after_bootstrap() {
    let service = service();
    let app = hs_server::app(service.clone());
    let (status, body) = send(&app, "GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepting_authorized_operations"], false);

    let token = service.create_bootstrap_token().expect("token");
    service
        .bootstrap(BootstrapRequest {
            bootstrap_token: token,
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_identity: None,
            manager_friendly_name: None,
        })
        .expect("bootstrap");

    let (status, body) = send(&app, "GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["bootstrap_completed"], true);
    assert_eq!(body["accepting_authorized_operations"], true);
}

#[tokio::test]
async fn bootstrap_is_single_use() {
    let service = service();
    let token = service.create_bootstrap_token().expect("token");
    let first = service.bootstrap(BootstrapRequest {
        bootstrap_token: token.clone(),
        username: "admin".into(),
        password: PASSWORD.into(),
        manager_public_identity: Some("mgr-admin".into()),
        manager_friendly_name: Some("Admin manager".into()),
    });
    assert!(first.is_ok(), "first bootstrap: {first:?}");

    let second = service.bootstrap(BootstrapRequest {
        bootstrap_token: token,
        username: "admin2".into(),
        password: "foundation-pass-2".into(),
        manager_public_identity: None,
        manager_friendly_name: None,
    });
    assert!(second.is_err(), "second bootstrap must fail");
}

#[tokio::test]
async fn invalid_session_is_rejected() {
    let app = app();
    let (status, body) = send(
        &app,
        "GET",
        "/v1/auth/session",
        Some("not-a-real-token"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "unauthorized");

    let (status, _) = send(&app, "GET", "/v1/auth/session", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pending_manager_cannot_login_until_approved() {
    let service = service();
    let admin = bootstrap_admin(&service);

    // Register a second manager as pending (development identity fixture).
    let pending = service
        .register_manager(
            &admin,
            RegisterManagerRequest {
                public_identity: "pending-manager".into(),
                friendly_name: "Pending lab manager".into(),
            },
        )
        .expect("register");
    assert_eq!(pending.lifecycle_state, "pending");

    // Login with pending manager is denied (D20: deny before approval).
    // Seam is v1 manager binding on a non-admin (administrator MFA is mandatory).
    seed_non_admin(&service, "mgr-operator", "operator-password-1");
    let denied = service.login(LoginRequest {
        username: "mgr-operator".into(),
        password: "operator-password-1".into(),
        manager_public_identity: Some("pending-manager".into()),
    });
    assert!(
        denied.is_err(),
        "pending manager must not bind to a session"
    );

    // Approve via authenticated enrollment admin (not self-approval).
    let approved = service
        .approve_manager(&admin, &pending.id, ApproveManagerRequest { confirm: true })
        .expect("approve");
    assert_eq!(approved.lifecycle_state, "approved");

    // Now login with the approved label-only manager succeeds.
    let login = service
        .login(LoginRequest {
            username: "mgr-operator".into(),
            password: "operator-password-1".into(),
            manager_public_identity: Some("pending-manager".into()),
        })
        .expect("login after approve");
    let auth = service.authenticate_token(&login.token).expect("auth");
    assert!(auth.manager_id.is_some());
}

#[tokio::test]
async fn scoped_inventory_denies_out_of_scope_computer() {
    let service = service();
    let admin = bootstrap_admin(&service);

    let mac = service
        .create_computer(
            &admin,
            CreateComputerRequest {
                public_identity: "endpoint-mac-1".into(),
                friendly_name: "Lab Mac".into(),
                platform: "macos".into(),
            },
        )
        .expect("computer mac");
    let win = service
        .create_computer(
            &admin,
            CreateComputerRequest {
                public_identity: "endpoint-win-1".into(),
                friendly_name: "Lab Windows".into(),
                platform: "windows".into(),
            },
        )
        .expect("computer win");

    // Explicit scope: only the Mac.
    let assignment = service
        .grant_access(
            &admin,
            GrantAccessRequest {
                account_id: admin.account_id.clone(),
                capability: "operate".into(),
                computer_ids: vec![mac.id.clone()],
                computer_scope_all: false,
            },
        )
        .expect("grant");
    assert_eq!(assignment.computer_ids, vec![mac.id.clone()]);

    service
        .require_computer_in_scope(&admin, &mac.id)
        .expect("mac in scope");
    let denied = service.require_computer_in_scope(&admin, &win.id);
    assert!(denied.is_err(), "windows computer must be out of scope");

    let list = service.list_computers(&admin).expect("list");
    assert!(list.scope_is_explicit);
    assert_eq!(list.computers.len(), 1);
    assert_eq!(list.computers[0].id, mac.id);
}

#[tokio::test]
async fn administration_does_not_imply_scope_or_pixels() {
    let service = service();
    let admin = bootstrap_admin(&service);
    // Bootstrap admin has manage_* flags; no automatic computer scope.
    let list = service.list_computers(&admin).expect("list");
    assert!(
        list.computers.is_empty(),
        "bootstrap admin must not inherit guessed computer grants"
    );
}

#[tokio::test]
async fn computer_groups_are_revisioned_and_never_grant_access() {
    let service = service();
    let (admin, token) = bootstrap_admin_with_manager_key(&service);
    let app = hs_server::app(service.clone());
    let visible = service
        .create_computer(
            &admin,
            CreateComputerRequest {
                public_identity: "group-visible-computer".into(),
                friendly_name: "Visible computer".into(),
                platform: "windows".into(),
            },
        )
        .expect("visible computer");
    let hidden = service
        .create_computer(
            &admin,
            CreateComputerRequest {
                public_identity: "group-hidden-computer".into(),
                friendly_name: "Hidden computer".into(),
                platform: "macos".into(),
            },
        )
        .expect("hidden computer");
    let assignment = service
        .grant_access(
            &admin,
            GrantAccessRequest {
                account_id: admin.account_id.clone(),
                capability: "observe".into(),
                computer_ids: vec![visible.id.clone()],
                computer_scope_all: false,
            },
        )
        .expect("explicit observe assignment");

    let (status, group) = send(
        &app,
        "POST",
        "/v2/groups",
        Some(&token),
        Some(json!({"name":"Lab West"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let group_id = group["id"].as_str().expect("group ID").to_string();
    assert_eq!(group["revision"], 1);

    let (status, groups) = send(&app, "GET", "/v2/groups", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(groups["groups"].as_array().expect("groups").len(), 1);
    assert!(groups["groups"][0].get("computer_ids").is_none());

    seed_non_admin(&service, "group-operator", "operator-password-3");
    let operator = service
        .login(LoginRequest {
            username: "group-operator".into(),
            password: "operator-password-3".into(),
            manager_public_identity: None,
        })
        .expect("non-admin login");
    let (status, _) = send(
        &app,
        "POST",
        "/v2/groups",
        Some(&operator.token),
        Some(json!({"name":"Unauthorized group"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    for (computer_id, revision) in [(&visible.id, 1), (&hidden.id, 2)] {
        let (status, body) = send(
            &app,
            "PUT",
            &format!("/v2/groups/{group_id}/computers/{computer_id}"),
            Some(&token),
            Some(json!({"expected_revision":revision,"included":true})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["revision"], revision + 1);
    }

    let (status, inventory) = send(&app, "GET", "/v1/computers", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        inventory["computers"].as_array().expect("inventory").len(),
        1
    );
    let computer = &inventory["computers"][0];
    assert_eq!(computer["id"], visible.id);
    assert_eq!(computer["groups"][0]["id"], group_id);
    assert_eq!(computer["groups"][0]["name"], "Lab West");
    assert!(
        service
            .require_computer_in_scope(&admin, &hidden.id)
            .is_err(),
        "membership must not grant inventory or operation scope"
    );

    let (status, enrollment_inventory) =
        send(&app, "GET", "/v2/enrollment/computers", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let enrollment_computers = enrollment_inventory["computers"]
        .as_array()
        .expect("enrollment inventory");
    assert_eq!(enrollment_computers.len(), 2);
    assert!(enrollment_computers
        .iter()
        .any(|computer| computer["id"] == hidden.id));
    assert!(enrollment_computers[0].get("public_identity").is_none());
    assert_eq!(enrollment_inventory["max_page_size"], 100);

    let (status, _) = send(
        &app,
        "GET",
        "/v2/enrollment/computers",
        Some(&operator.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, stale) = send(
        &app,
        "PUT",
        &format!("/v2/groups/{group_id}/computers/{}", visible.id),
        Some(&token),
        Some(json!({"expected_revision":1,"included":false})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(stale["error"]["code"], "conflict");

    let (status, duplicate) = send(
        &app,
        "POST",
        "/v2/groups",
        Some(&token),
        Some(json!({"name":"lab west"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(duplicate["error"]["code"], "conflict");

    let (status, renamed) = send(
        &app,
        "PUT",
        &format!("/v2/groups/{group_id}"),
        Some(&token),
        Some(json!({"expected_revision":3,"name":"West"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(renamed["revision"], 4);
    assert_eq!(renamed["name"], "West");

    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/v2/groups/{group_id}"),
        Some(&token),
        Some(json!({"expected_revision":4,"confirm_group_id":"wrong"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/v2/groups/{group_id}"),
        Some(&token),
        Some(json!({"expected_revision":4,"confirm_group_id":group_id})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let after_delete = service.list_access(&admin).expect("access remains");
    assert_eq!(after_delete.len(), 1);
    assert_eq!(after_delete[0].id, assignment.id);
    assert_eq!(after_delete[0].computer_ids, vec![visible.id]);
}

#[tokio::test]
async fn endpoint_enrollment_requires_proof_then_explicit_epoch_fenced_approval() {
    let service = service();
    let (admin, token) = bootstrap_admin_with_manager_key(&service);
    let app = hs_server::app(service.clone());

    let (status, issued) = send(
        &app,
        "POST",
        "/v2/enrollment/invitations",
        Some(&token),
        Some(json!({"friendly_name":"Lab Windows","platform":"windows"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let invitation_id = issued["id"].as_str().expect("invitation ID");
    let deployment_id = issued["deployment_id"].as_str().expect("deployment ID");
    let enrollment_code = issued["enrollment_code"].as_str().expect("one-time code");
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let code_hash = hs_server::crypto::hash_token(enrollment_code);

    {
        let conn = service.db_handle().lock().expect("store");
        let stored_hash: String = conn
            .query_row(
                "SELECT code_hash FROM computer_enrollment_invitations WHERE id = ?1",
                rusqlite::params![invitation_id],
                |row| row.get(0),
            )
            .expect("stored invitation hash");
        assert_eq!(stored_hash, code_hash);
        assert_ne!(stored_hash, enrollment_code);
    }

    let proof_message = hs_server::crypto::endpoint_enrollment_proof_message(
        deployment_id,
        invitation_id,
        &code_hash,
        &public_key,
    );
    let bad_signature = hex::encode(
        SigningKey::from_bytes(&[9_u8; 32])
            .sign(&proof_message)
            .to_bytes(),
    );
    let enrollment_body = |proof: String| {
        json!({
            "invitation_id":invitation_id,
            "enrollment_code":enrollment_code,
            "public_key":public_key,
            "proof":proof
        })
    };
    let (status, _) = send(
        &app,
        "POST",
        "/v2/endpoints/enroll",
        None,
        Some(enrollment_body(bad_signature)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let signature = hex::encode(signing_key.sign(&proof_message).to_bytes());
    let (status, enrolled) = send(
        &app,
        "POST",
        "/v2/endpoints/enroll",
        None,
        Some(enrollment_body(signature.clone())),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{enrolled}");
    let computer_id = enrolled["computer"]["id"]
        .as_str()
        .expect("pending computer ID");
    assert_eq!(enrolled["computer"]["enrollment_state"], "pending");
    assert_eq!(enrolled["computer"]["enrollment_epoch"], 1);
    assert!(enrolled["computer"].get("public_identity").is_none());

    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64;
    let pending_nonce = "dd".repeat(32);
    let pending_proof = hs_server::crypto::endpoint_session_begin_proof_message(
        deployment_id,
        computer_id,
        issued_at,
        &pending_nonce,
    );
    let (status, _) = send(
        &app,
        "POST",
        "/v2/endpoints/session/challenge",
        None,
        Some(json!({
            "computer_id":computer_id,
            "client_nonce":pending_nonce,
            "issued_at_unix":issued_at,
            "proof":hex::encode(signing_key.sign(&pending_proof).to_bytes())
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "pending endpoint has no session authority"
    );

    let (status, invitations) = send(
        &app,
        "GET",
        "/v2/enrollment/invitations",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(invitations["invitations"][0]["state"], "redeemed");
    assert!(invitations["invitations"][0]
        .get("enrollment_code")
        .is_none());
    assert!(invitations["invitations"][0].get("code_hash").is_none());

    let (status, replay) = send(
        &app,
        "POST",
        "/v2/endpoints/enroll",
        None,
        Some(enrollment_body(signature)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(replay["error"]["message"]
        .as_str()
        .expect("replay error")
        .contains("invalid or expired"));

    let approval = json!({
        "expected_enrollment_epoch":1,
        "confirm_computer_id":computer_id
    });
    let (status, approved) = send(
        &app,
        "POST",
        &format!("/v2/enrollment/computers/{computer_id}/approve"),
        Some(&token),
        Some(approval),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["enrollment_state"], "enrolled");
    assert_eq!(approved["enrollment_epoch"], 2);

    // Admission is a fresh proof exchange. Challenge tokens and endpoint
    // sessions are single use, hashed at rest, and fenced by the approval epoch.
    let client_nonce = "ab".repeat(32);
    let local_user_id = "windows:sid:S-1-5-21-1000";
    let local_user_display_name = "Lab User";
    let begin_proof = hs_server::crypto::endpoint_session_begin_proof_message_for_user_label(
        deployment_id,
        computer_id,
        local_user_id,
        local_user_display_name,
        issued_at,
        &client_nonce,
    );
    let (status, challenge) = send(
        &app,
        "POST",
        "/v2/endpoints/session/challenge",
        None,
        Some(json!({
            "computer_id":computer_id,
            "local_user_id":local_user_id,
            "local_user_display_name":local_user_display_name,
            "client_nonce":client_nonce,
            "issued_at_unix":issued_at,
            "proof":hex::encode(signing_key.sign(&begin_proof).to_bytes())
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{challenge}");
    assert_eq!(challenge["deployment_id"], deployment_id);
    assert_eq!(challenge["computer_id"], computer_id);
    assert_eq!(challenge["enrollment_epoch"], 2);
    let (status, _) = send(
        &app,
        "POST",
        "/v2/endpoints/session/challenge",
        None,
        Some(json!({
            "computer_id":computer_id,
            "local_user_id":local_user_id,
            "local_user_display_name":local_user_display_name,
            "client_nonce":client_nonce,
            "issued_at_unix":issued_at,
            "proof":hex::encode(signing_key.sign(&begin_proof).to_bytes())
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "client nonce replays are denied"
    );
    let challenge_id = challenge["challenge_id"].as_str().expect("challenge ID");
    let challenge_token = challenge["challenge_token"]
        .as_str()
        .expect("challenge token");
    let challenge_token_hash = hs_server::crypto::hash_token(challenge_token);
    let session_proof = hs_server::crypto::endpoint_session_proof_message_for_user_label(
        deployment_id,
        challenge_id,
        &challenge_token_hash,
        computer_id,
        2,
        &public_key,
        local_user_id,
        local_user_display_name,
    );
    let wrong_signature = hex::encode(
        SigningKey::from_bytes(&[29_u8; 32])
            .sign(&session_proof)
            .to_bytes(),
    );
    let complete_body = |signature: String| {
        json!({
            "challenge_id":challenge_id,
            "challenge_token":challenge_token,
            "signature":signature
        })
    };
    let (status, _) = send(
        &app,
        "POST",
        "/v2/endpoints/session/complete",
        None,
        Some(complete_body(wrong_signature)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, session) = send(
        &app,
        "POST",
        "/v2/endpoints/session/complete",
        None,
        Some(complete_body(hex::encode(
            signing_key.sign(&session_proof).to_bytes(),
        ))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["computer_id"], computer_id);
    assert_eq!(session["enrollment_epoch"], 2);
    assert!(session["session_id"]
        .as_str()
        .is_some_and(|value| uuid::Uuid::parse_str(value).is_ok()));
    let endpoint_token = session["token"].as_str().expect("endpoint token");
    {
        let conn = service.db_handle().lock().expect("store");
        let stored_hash: String = conn
            .query_row(
                "SELECT token_hash FROM endpoint_sessions WHERE computer_id = ?1",
                rusqlite::params![computer_id],
                |row| row.get(0),
            )
            .expect("endpoint session hash");
        assert_eq!(stored_hash, hs_server::crypto::hash_token(endpoint_token));
        assert_ne!(stored_hash, endpoint_token);
    }
    let (status, endpoint_self) = send(
        &app,
        "GET",
        "/v2/endpoints/self",
        Some(endpoint_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{endpoint_self}");
    assert_eq!(endpoint_self["computer_id"], computer_id);
    assert_eq!(endpoint_self["friendly_name"], "Lab Windows");
    assert!(endpoint_self.get("public_identity").is_none());
    let (status, _) = send(
        &app,
        "POST",
        "/v2/endpoints/session/complete",
        None,
        Some(complete_body(hex::encode(
            signing_key.sign(&session_proof).to_bytes(),
        ))),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "challenge completion replays are denied"
    );

    // File delivery requires a separate operate assignment and preserves each
    // target's durable result. The server never releases an unverified object.
    let payload = b"hello endpoint";
    let payload_sha = hex::encode(Sha256::digest(payload));
    let denied_file_body = json!({
        "file_name":"instructions.txt",
        "file_size_bytes":payload.len(),
        "sha256":payload_sha,
        "computer_ids":[computer_id],
        "expected_recipients":[{
            "computer_id":computer_id,
            "session_id":"00000000-0000-4000-8000-000000000000"
        }]
    });
    let (status, denied_file_job) = send(
        &app,
        "POST",
        "/v2/files/jobs",
        Some(&token),
        Some(denied_file_body),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "enrollment alone grants no operate access"
    );
    assert!(denied_file_job.get("id").is_none());
    {
        let conn = service.db_handle().lock().expect("store");
        let now = hs_server::db::now_unix();
        conn.execute(
            "INSERT INTO access_assignments (
                id, account_id, capability, computer_scope_all, revision, created_at, updated_at
             ) VALUES (?1, ?2, 'operate', 0, 1, ?3, ?3)",
            rusqlite::params![format!("operate-{computer_id}"), admin.account_id, now],
        )
        .expect("operate assignment");
        conn.execute(
            "INSERT INTO access_computer_scope (assignment_id, computer_id)
             VALUES (?1, ?2)",
            rusqlite::params![format!("operate-{computer_id}"), computer_id],
        )
        .expect("operate scope");
    }
    let (status, recipient) = send(
        &app,
        "GET",
        &format!("/v2/files/recipients/{computer_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{recipient}");
    assert_eq!(recipient["computer_id"], computer_id);
    assert_eq!(recipient["display_name"], "Lab User");
    let endpoint_session_id = recipient["session_id"]
        .as_str()
        .expect("preflight endpoint session ID");
    let create_file_body = json!({
        "file_name":"instructions.txt",
        "file_size_bytes":payload.len(),
        "sha256":payload_sha,
        "computer_ids":[computer_id],
        "expected_recipients":[{
            "computer_id":computer_id,
            "session_id":endpoint_session_id
        }]
    });
    let (status, file_job) = send(
        &app,
        "POST",
        "/v2/files/jobs",
        Some(&token),
        Some(create_file_body),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{file_job}");
    assert_eq!(file_job["state"], "uploading");
    assert_eq!(file_job["targets"][0]["state"], "awaiting_upload");
    let file_job_id = file_job["id"].as_str().expect("file job ID");
    let (status, _, wrong_upload) = send_bytes(
        &app,
        "PUT",
        &format!("/v2/files/jobs/{file_job_id}/chunks/0"),
        Some(&token),
        b"wrong payload!",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let wrong_upload: Value = serde_json::from_slice(&wrong_upload).expect("chunk receipt");
    assert_eq!(wrong_upload["state"], "uploading");
    assert_eq!(wrong_upload["finalized"], false);
    let (status, _, receipt_bytes) = send_bytes(
        &app,
        "PUT",
        &format!("/v2/files/jobs/{file_job_id}/chunks/0"),
        Some(&token),
        payload,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let receipt: Value = serde_json::from_slice(&receipt_bytes).expect("chunk receipt");
    assert_eq!(receipt["state"], "queued");
    assert_eq!(receipt["finalized"], true);

    let (status, _) = send(&app, "GET", "/v2/endpoints/jobs", Some(&token), None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "manager tokens are not endpoint sessions"
    );
    let (status, endpoint_jobs) = send(
        &app,
        "GET",
        "/v2/endpoints/jobs",
        Some(endpoint_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{endpoint_jobs}");
    assert_eq!(endpoint_jobs["jobs"][0]["id"], file_job_id);
    assert_eq!(endpoint_jobs["jobs"][0]["state"], "in_progress");
    let (status, _, _) = send_bytes(
        &app,
        "GET",
        &format!("/v2/endpoints/jobs/{file_job_id}/chunks/0"),
        Some(&token),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, chunk_headers, downloaded_payload) = send_bytes(
        &app,
        "GET",
        &format!("/v2/endpoints/jobs/{file_job_id}/chunks/0"),
        Some(endpoint_token),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(downloaded_payload, payload);
    assert_eq!(
        chunk_headers
            .get("x-helicoid-chunk-sha256")
            .and_then(|value| value.to_str().ok()),
        Some(payload_sha.as_str())
    );
    let (status, wrong_result) = send(
        &app,
        "POST",
        &format!("/v2/endpoints/jobs/{file_job_id}/result"),
        Some(endpoint_token),
        Some(json!({
            "succeeded":true,
            "received_size_bytes":payload.len(),
            "received_sha256":"00".repeat(32)
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{wrong_result}");
    let (status, result) = send(
        &app,
        "POST",
        &format!("/v2/endpoints/jobs/{file_job_id}/result"),
        Some(endpoint_token),
        Some(json!({
            "succeeded":true,
            "received_size_bytes":payload.len(),
            "received_sha256":payload_sha
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["target"]["state"], "completed");
    let (status, completed_job) = send(
        &app,
        "GET",
        &format!("/v2/files/jobs/{file_job_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{completed_job}");
    assert_eq!(completed_job["state"], "completed");
    assert_eq!(completed_job["targets"][0]["received_sha256"], payload_sha);
    {
        let conn = service.db_handle().lock().expect("store");
        let chunk_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_job_chunks WHERE job_id = ?1",
                rusqlite::params![file_job_id],
                |row| row.get(0),
            )
            .expect("payload retention count");
        assert_eq!(chunk_count, 0, "terminal payload bytes are released");
    }

    let empty_sha = hex::encode(Sha256::digest([]));
    let (status, queued_empty) = send(
        &app,
        "POST",
        "/v2/files/jobs",
        Some(&token),
        Some(json!({
            "file_name":"empty.txt",
            "file_size_bytes":0,
            "sha256":empty_sha,
            "computer_ids":[computer_id],
            "expected_recipients":[{
                "computer_id":computer_id,
                "session_id":endpoint_session_id
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{queued_empty}");
    assert_eq!(queued_empty["state"], "queued");
    let empty_job_id = queued_empty["id"].as_str().expect("empty job ID");
    let (status, _) = send(
        &app,
        "POST",
        &format!("/v2/files/jobs/{empty_job_id}"),
        Some(&token),
        Some(json!({"confirm_job_id":"different-job"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, cancelled_empty) = send(
        &app,
        "POST",
        &format!("/v2/files/jobs/{empty_job_id}"),
        Some(&token),
        Some(json!({"confirm_job_id":empty_job_id})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{cancelled_empty}");
    assert_eq!(cancelled_empty["state"], "cancelled");

    let (status, queued_failure) = send(
        &app,
        "POST",
        "/v2/files/jobs",
        Some(&token),
        Some(json!({
            "file_name":"will-fail.txt",
            "file_size_bytes":payload.len(),
            "sha256":payload_sha,
            "computer_ids":[computer_id],
            "expected_recipients":[{
                "computer_id":computer_id,
                "session_id":endpoint_session_id
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{queued_failure}");
    let failure_job_id = queued_failure["id"].as_str().expect("failure job ID");
    let (status, _, _) = send_bytes(
        &app,
        "PUT",
        &format!("/v2/files/jobs/{failure_job_id}/chunks/0"),
        Some(&token),
        payload,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, failure_jobs) = send(
        &app,
        "GET",
        "/v2/endpoints/jobs",
        Some(endpoint_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{failure_jobs}");
    assert_eq!(failure_jobs["jobs"][0]["id"], failure_job_id);
    let (status, _) = send(
        &app,
        "POST",
        &format!("/v2/files/jobs/{failure_job_id}"),
        Some(&token),
        Some(json!({"confirm_job_id":failure_job_id})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "leased work is committed");
    let (status, failed_result) = send(
        &app,
        "POST",
        &format!("/v2/endpoints/jobs/{failure_job_id}/result"),
        Some(endpoint_token),
        Some(json!({"succeeded":false,"detail":"destination unavailable"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{failed_result}");
    let (status, failed_job) = send(
        &app,
        "GET",
        &format!("/v2/files/jobs/{failure_job_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{failed_job}");
    assert_eq!(failed_job["state"], "failed");
    assert_eq!(
        failed_job["targets"][0]["result_detail"],
        "destination unavailable"
    );

    // Reverse file requests are manager-owned and user-bound at submission
    // time. Exercise the HTTP routes end to end so both auth domains, chunk
    // verification, review, and explicit content deletion stay covered.
    let (status, created_request) = send(
        &app,
        "POST",
        "/v2/files/requests",
        Some(&token),
        Some(json!({
            "title":"Collect client log",
            "instructions":"Upload the diagnostic log as a .txt file.",
            "computer_ids":[computer_id],
            "allowed_extensions":["txt"],
            "max_file_count":1,
            "max_total_size_bytes":1024,
            "closes_at_unix":hs_server::db::now_unix() + 600,
            "replacement_allowed":true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created_request}");
    assert_eq!(created_request["state"], "draft");
    let file_request_id = created_request["id"]
        .as_str()
        .expect("file request ID")
        .to_owned();

    let (status, _) = send(
        &app,
        "GET",
        "/v2/endpoints/file-requests",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "manager token is not endpoint authority"
    );
    let (status, published_request) = send(
        &app,
        "POST",
        &format!("/v2/files/requests/{file_request_id}/publish"),
        Some(&token),
        Some(json!({"expected_revision":1})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{published_request}");
    assert_eq!(published_request["state"], "open");
    assert_eq!(published_request["revision"], 2);

    let (status, endpoint_requests) = send(
        &app,
        "GET",
        "/v2/endpoints/file-requests",
        Some(endpoint_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{endpoint_requests}");
    assert_eq!(endpoint_requests["requests"].as_array().unwrap().len(), 1);
    assert_eq!(endpoint_requests["requests"][0]["id"], file_request_id);
    assert_eq!(endpoint_requests["requests"][0]["revision"], 2);

    let file_request_payload = b"diagnostic details";
    let file_request_sha = hex::encode(Sha256::digest(file_request_payload));
    let (status, uploading_submission) = send(
        &app,
        "POST",
        &format!("/v2/endpoints/file-requests/{file_request_id}/submissions"),
        Some(endpoint_token),
        Some(json!({
            "request_revision":2,
            "files":[{
                "file_name":"client-log.txt",
                "file_size_bytes":file_request_payload.len(),
                "sha256":file_request_sha
            }],
            "replace_submission_id":null,
            "confirm_replacement":false
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{uploading_submission}");
    assert_eq!(uploading_submission["state"], "uploading");
    assert_eq!(
        uploading_submission["local_user_display_name"],
        local_user_display_name
    );
    let submission_id = uploading_submission["id"]
        .as_str()
        .expect("submission ID")
        .to_owned();
    let submission_file_id = uploading_submission["files"][0]["id"]
        .as_str()
        .expect("submission file ID")
        .to_owned();

    let (status, endpoint_submissions) = send(
        &app,
        "GET",
        &format!("/v2/endpoints/file-requests/{file_request_id}/submissions"),
        Some(endpoint_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{endpoint_submissions}");
    assert_eq!(endpoint_submissions[0]["id"], submission_id);
    let upload_chunk_path = format!(
        "/v2/endpoints/file-requests/{file_request_id}/submissions/{submission_id}/files/{submission_file_id}/chunks/0"
    );
    let (status, _, chunk_receipt_bytes) = send_bytes(
        &app,
        "PUT",
        &upload_chunk_path,
        Some(endpoint_token),
        file_request_payload,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let chunk_receipt: Value = serde_json::from_slice(&chunk_receipt_bytes).expect("chunk receipt");
    assert_eq!(chunk_receipt["submission_id"], submission_id);
    assert_eq!(chunk_receipt["sha256"], file_request_sha);
    let (status, received_submission) = send(
        &app,
        "POST",
        &format!(
            "/v2/endpoints/file-requests/{file_request_id}/submissions/{submission_id}/complete"
        ),
        Some(endpoint_token),
        Some(json!({
            "request_revision":2,
            "confirm_submission_id":submission_id
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{received_submission}");
    assert_eq!(received_submission["state"], "received");
    assert_eq!(received_submission["files"][0]["state"], "received");

    // Replacing a received submission is a one-way, explicit transition. The
    // earlier content is removed only when its replacement is fully verified.
    let replacement_payload = b"replacement diagnostic details";
    let replacement_sha = hex::encode(Sha256::digest(replacement_payload));
    let replacement_manifest = json!([{
        "file_name":"replacement.txt",
        "file_size_bytes":replacement_payload.len(),
        "sha256":replacement_sha
    }]);
    let (status, _) = send(
        &app,
        "POST",
        &format!("/v2/endpoints/file-requests/{file_request_id}/submissions"),
        Some(endpoint_token),
        Some(json!({
            "request_revision":2,
            "files":replacement_manifest,
            "replace_submission_id":submission_id,
            "confirm_replacement":false
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "replacement needs confirmation"
    );
    let (status, replacement_submission) = send(
        &app,
        "POST",
        &format!("/v2/endpoints/file-requests/{file_request_id}/submissions"),
        Some(endpoint_token),
        Some(json!({
            "request_revision":2,
            "files":replacement_manifest,
            "replace_submission_id":submission_id,
            "confirm_replacement":true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{replacement_submission}");
    let replacement_submission_id = replacement_submission["id"]
        .as_str()
        .expect("replacement submission ID")
        .to_owned();
    let replacement_file_id = replacement_submission["files"][0]["id"]
        .as_str()
        .expect("replacement file ID")
        .to_owned();
    let replacement_upload_path = format!(
        "/v2/endpoints/file-requests/{file_request_id}/submissions/{replacement_submission_id}/files/{replacement_file_id}/chunks/0"
    );
    let (status, _, _) = send_bytes(
        &app,
        "PUT",
        &replacement_upload_path,
        Some(endpoint_token),
        replacement_payload,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, completed_replacement) = send(
        &app,
        "POST",
        &format!(
            "/v2/endpoints/file-requests/{file_request_id}/submissions/{replacement_submission_id}/complete"
        ),
        Some(endpoint_token),
        Some(json!({
            "request_revision":2,
            "confirm_submission_id":replacement_submission_id
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{completed_replacement}");
    assert_eq!(completed_replacement["state"], "received");
    assert_eq!(
        completed_replacement["replaces_submission_id"],
        submission_id
    );

    // A fresh admitted OS user fences the prior endpoint session. The new
    // user's token must not resume, replace, or download the first user's
    // submission even though both identities share the same display name and
    // computer.
    let second_local_user_id = "windows:sid:S-1-5-21-2000";
    let second_local_user_display_name = local_user_display_name;
    let second_nonce = "ef".repeat(32);
    let second_begin_proof = hs_server::crypto::endpoint_session_begin_proof_message_for_user_label(
        deployment_id,
        computer_id,
        second_local_user_id,
        second_local_user_display_name,
        issued_at,
        &second_nonce,
    );
    let (status, second_challenge) = send(
        &app,
        "POST",
        "/v2/endpoints/session/challenge",
        None,
        Some(json!({
            "computer_id":computer_id,
            "local_user_id":second_local_user_id,
            "local_user_display_name":second_local_user_display_name,
            "client_nonce":second_nonce,
            "issued_at_unix":issued_at,
            "proof":hex::encode(signing_key.sign(&second_begin_proof).to_bytes())
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{second_challenge}");
    let second_challenge_id = second_challenge["challenge_id"]
        .as_str()
        .expect("second challenge ID");
    let second_challenge_token = second_challenge["challenge_token"]
        .as_str()
        .expect("second challenge token");
    let second_session_proof = hs_server::crypto::endpoint_session_proof_message_for_user_label(
        deployment_id,
        second_challenge_id,
        &hs_server::crypto::hash_token(second_challenge_token),
        computer_id,
        2,
        &public_key,
        second_local_user_id,
        second_local_user_display_name,
    );
    let (status, second_session) = send(
        &app,
        "POST",
        "/v2/endpoints/session/complete",
        None,
        Some(json!({
            "challenge_id":second_challenge_id,
            "challenge_token":second_challenge_token,
            "signature":hex::encode(signing_key.sign(&second_session_proof).to_bytes())
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second_session}");
    let second_endpoint_token = second_session["token"]
        .as_str()
        .expect("second endpoint token");
    let (status, second_recipient) = send(
        &app,
        "GET",
        &format!("/v2/files/recipients/{computer_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second_recipient}");
    assert_eq!(second_recipient["display_name"], local_user_display_name);
    let second_endpoint_session_id = second_recipient["session_id"]
        .as_str()
        .expect("second endpoint session ID");
    let (status, _) = send(
        &app,
        "GET",
        "/v2/endpoints/file-requests",
        Some(endpoint_token),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "user switch fences old endpoint session"
    );
    let (status, second_user_submissions) = send(
        &app,
        "GET",
        &format!("/v2/endpoints/file-requests/{file_request_id}/submissions"),
        Some(second_endpoint_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second_user_submissions}");
    assert_eq!(second_user_submissions.as_array().unwrap().len(), 0);
    let (status, _, _) = send_bytes(
        &app,
        "PUT",
        &replacement_upload_path,
        Some(second_endpoint_token),
        replacement_payload,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another local user cannot write into a received submission"
    );
    let (status, replacement_denied) = send(
        &app,
        "POST",
        &format!("/v2/endpoints/file-requests/{file_request_id}/submissions"),
        Some(second_endpoint_token),
        Some(json!({
            "request_revision":2,
            "files":[{
                "file_name":"replacement.txt",
                "file_size_bytes":file_request_payload.len(),
                "sha256":file_request_sha
            }],
            "replace_submission_id":replacement_submission_id,
            "confirm_replacement":true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{replacement_denied}");

    let (status, _) = send(
        &app,
        "GET",
        &format!("/v2/files/requests/{file_request_id}/submissions"),
        Some(endpoint_token),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "endpoint token is not manager authority"
    );
    let (status, reviewed_submissions) = send(
        &app,
        "GET",
        &format!("/v2/files/requests/{file_request_id}/submissions"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reviewed_submissions}");
    let prior_submission = reviewed_submissions
        .as_array()
        .unwrap()
        .iter()
        .find(|submission| submission["id"] == submission_id)
        .expect("prior submission remains in review history");
    assert_eq!(prior_submission["state"], "superseded");
    assert_eq!(prior_submission["files"][0]["state"], "deleted");
    let replacement_record = reviewed_submissions
        .as_array()
        .unwrap()
        .iter()
        .find(|submission| submission["id"] == replacement_submission_id)
        .expect("replacement submission remains in review history");
    assert_eq!(replacement_record["state"], "received");
    let download_chunk_path = format!(
        "/v2/files/requests/{file_request_id}/submissions/{replacement_submission_id}/files/{replacement_file_id}/chunks/0"
    );
    let (status, _, downloaded_file_request_payload) =
        send_bytes(&app, "GET", &download_chunk_path, Some(&token), &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(downloaded_file_request_payload, replacement_payload);
    let (status, deleted_content) = send(
        &app,
        "DELETE",
        &format!("/v2/files/requests/{file_request_id}/submissions/{replacement_submission_id}"),
        Some(&token),
        Some(json!({"confirm_submission_id":replacement_submission_id})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted_content}");
    assert_eq!(
        deleted_content["content_deleted_by_account_id"],
        admin.account_id
    );
    let (status, _, deleted_payload) =
        send_bytes(&app, "GET", &download_chunk_path, Some(&token), &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        !deleted_payload.is_empty(),
        "the API returns its not-found error"
    );

    let (status, revocation_job) = send(
        &app,
        "POST",
        "/v2/files/jobs",
        Some(&token),
        Some(json!({
            "file_name":"revoked-endpoint.txt",
            "file_size_bytes":payload.len(),
            "sha256":payload_sha,
            "computer_ids":[computer_id],
            "expected_recipients":[{
                "computer_id":computer_id,
                "session_id":second_endpoint_session_id
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{revocation_job}");
    let revocation_job_id = revocation_job["id"].as_str().expect("revocation job ID");
    let (status, _, _) = send_bytes(
        &app,
        "PUT",
        &format!("/v2/files/jobs/{revocation_job_id}/chunks/0"),
        Some(&token),
        payload,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, leased_revocation_job) = send(
        &app,
        "GET",
        "/v2/endpoints/jobs",
        Some(second_endpoint_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{leased_revocation_job}");
    assert_eq!(leased_revocation_job["jobs"][0]["id"], revocation_job_id);

    let (status, stale) = send(
        &app,
        "POST",
        &format!("/v2/enrollment/computers/{computer_id}/approve"),
        Some(&token),
        Some(json!({
            "expected_enrollment_epoch":1,
            "confirm_computer_id":computer_id
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(stale["error"]["code"], "conflict");

    let (status, revoked) = send(
        &app,
        "POST",
        &format!("/v2/enrollment/computers/{computer_id}/revoke"),
        Some(&token),
        Some(json!({
            "expected_enrollment_epoch":2,
            "confirm_computer_id":computer_id
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert_eq!(revoked["enrollment_state"], "revoked");
    assert_eq!(revoked["enrollment_epoch"], 3);
    let (status, _) = send(
        &app,
        "GET",
        "/v2/endpoints/self",
        Some(second_endpoint_token),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "revocation fences issued sessions"
    );
    let (status, revoked_job) = send(
        &app,
        "GET",
        &format!("/v2/files/jobs/{revocation_job_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked_job}");
    assert_eq!(revoked_job["state"], "failed");
    assert_eq!(
        revoked_job["targets"][0]["result_detail"],
        "endpoint_revoked"
    );

    let conn = service.db_handle().lock().expect("store");
    let (identity, state, epoch, incarnation): (String, String, i64, Option<String>) = conn
        .query_row(
            "SELECT public_identity, enrollment_state, enrollment_epoch,
                    approved_incarnation_identity
             FROM computers WHERE id = ?1",
            rusqlite::params![computer_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("persisted endpoint");
    assert_eq!(identity, format!("key:{public_key}"));
    assert_eq!(state, "revoked");
    assert_eq!(epoch, 3);
    assert_eq!(incarnation.as_deref(), Some(identity.as_str()));
}

#[tokio::test]
async fn endpoint_invitation_can_be_revoked_without_exposing_its_code() {
    let service = service();
    let (_admin, token) = bootstrap_admin_with_manager_key(&service);
    let app = hs_server::app(service.clone());
    let (status, issued) = send(
        &app,
        "POST",
        "/v2/enrollment/invitations",
        Some(&token),
        Some(json!({"friendly_name":"Spare Mac","platform":"macos"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let invitation_id = issued["id"].as_str().expect("invitation ID");

    let (status, _) = send(
        &app,
        "POST",
        &format!("/v2/enrollment/invitations/{invitation_id}/revoke"),
        Some(&token),
        Some(json!({"confirm_invitation_id":"different-id"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, revoked) = send(
        &app,
        "POST",
        &format!("/v2/enrollment/invitations/{invitation_id}/revoke"),
        Some(&token),
        Some(json!({"confirm_invitation_id":invitation_id})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert_eq!(revoked["state"], "revoked");

    let public_key = hex::encode(
        SigningKey::from_bytes(&[11_u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    let (status, _) = send(
        &app,
        "POST",
        "/v2/endpoints/enroll",
        None,
        Some(json!({
            "invitation_id":invitation_id,
            "enrollment_code":issued["enrollment_code"],
            "public_key":public_key,
            "proof":"00".repeat(64)
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, invitations) = send(
        &app,
        "GET",
        "/v2/enrollment/invitations",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(invitations["invitations"][0]["state"], "revoked");
    assert!(invitations["invitations"][0]
        .get("enrollment_code")
        .is_none());

    let conn = service.db_handle().lock().expect("store");
    let computer_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM computers", [], |row| row.get(0))
        .expect("computer count");
    assert_eq!(
        computer_count, 0,
        "revoked code creates no pending computer"
    );
}

#[tokio::test]
async fn endpoint_invitation_requires_fresh_mfa_in_persisted_session() {
    let service = service();
    let (admin, token) = bootstrap_admin_with_manager_key(&service);
    let app = hs_server::app(service.clone());
    let now = hs_server::db::now_unix();
    {
        let conn = service.db_handle().lock().expect("store");
        conn.execute(
            "UPDATE sessions SET mfa_assured_at = ?1 WHERE id = ?2",
            rusqlite::params![now - 121, admin.session_id],
        )
        .expect("stale persisted MFA assurance");
    }

    let (status, _) = send(
        &app,
        "POST",
        "/v2/enrollment/invitations",
        Some(&token),
        Some(json!({"friendly_name":"Stale Admin","platform":"linux"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let conn = service.db_handle().lock().expect("store");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM computer_enrollment_invitations",
            [],
            |row| row.get(0),
        )
        .expect("invitation count");
    assert_eq!(count, 0, "stale MFA must not create a pending invitation");
}

#[tokio::test]
async fn competing_unique_claims_conflict() {
    let service = service();
    let admin = bootstrap_admin(&service);

    service
        .create_computer(
            &admin,
            CreateComputerRequest {
                public_identity: "shared-key".into(),
                friendly_name: "First".into(),
                platform: "macos".into(),
            },
        )
        .expect("first computer");

    let second = service.create_computer(
        &admin,
        CreateComputerRequest {
            public_identity: "shared-key".into(),
            friendly_name: "Second".into(),
            platform: "windows".into(),
        },
    );
    assert!(second.is_err(), "duplicate public_identity must conflict");
}

#[tokio::test]
async fn revoked_manager_session_is_invalid() {
    let service = service();
    let admin = bootstrap_admin(&service);
    seed_non_admin(&service, "revoked-op", "operator-password-2");
    let login = service
        .login(LoginRequest {
            username: "revoked-op".into(),
            password: "operator-password-2".into(),
            manager_public_identity: Some("admin-manager".into()),
        })
        .expect("login with manager");
    let auth = service.authenticate_token(&login.token).expect("auth");
    let manager_id = auth.manager_id.clone().expect("manager bound");

    service.revoke_manager(&admin, &manager_id).expect("revoke");

    let after = service.authenticate_token(&login.token);
    assert!(
        after.is_err(),
        "sessions bound to a revoked manager must fail"
    );
}

#[tokio::test]
async fn legacy_v1_file_jobs_and_recovery_are_explicitly_unavailable() {
    let app = app();
    let (status, body) = send(&app, "POST", "/v1/files/jobs", None, Some(json!({}))).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["available"], false);

    let (status, body) = send(&app, "POST", "/v1/security/recovery", None, Some(json!({}))).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["available"], false);

    let (status, body) = send(&app, "GET", "/v1/mfa/status", None, None).await;
    assert_eq!(status, StatusCode::OK);
    // Real TOTP MFA is implemented behind auth v2; v1 status reports availability.
    assert_eq!(body["available"], true);
    assert_eq!(body["required"], true);
}

#[tokio::test]
async fn refuses_unrelated_database_file() {
    let (_dir, base) = private_tempdir();
    let path = base.join("unrelated.db");
    {
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.execute_batch("CREATE TABLE notes (id INTEGER PRIMARY KEY)")
            .expect("unrelated table");
    }
    let err = match db::open(&path) {
        Ok(_) => panic!("must refuse unrelated db"),
        Err(err) => err,
    };
    let message = err.to_string();
    assert!(
        message.contains("refusing") || message.contains("not empty"),
        "msg={message}"
    );
}

#[tokio::test]
async fn fresh_database_initializes_schema() {
    let (_dir, base) = private_tempdir();
    let path = base.join("fresh.db");
    let db = db::open(&path).expect("fresh open");
    let conn = db.lock().expect("lock");
    let version: i64 = conn
        .query_row(
            "SELECT schema_version FROM schema_meta WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .expect("schema_meta");
    assert_eq!(version, db::SCHEMA_VERSION);
}
