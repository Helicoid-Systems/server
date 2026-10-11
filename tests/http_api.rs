//! HTTP integration tests for contract v1.
//!
//! Covers deny-before-approval, scoped inventory, invalid session, competing
//! unique claims, single-use bootstrap, and schema initialization refusals.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
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
        serde_json::from_slice(&bytes).expect("json body")
    };
    (status, value)
}

/// Bootstrap the first administrator (single-use) and return an authenticated context.
fn bootstrap_admin(service: &Service) -> hs_server::service::AuthContext {
    let token = service.create_bootstrap_token().expect("bootstrap token");
    service
        .bootstrap(BootstrapRequest {
            bootstrap_token: token,
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_identity: Some("admin-manager".into()),
            manager_friendly_name: Some("Admin manager".into()),
        })
        .expect("bootstrap");
    let login = service
        .login(LoginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_identity: None,
        })
        .expect("login");
    service.authenticate_token(&login.token).expect("auth")
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
    assert_eq!(body["features"]["file_jobs"], false);
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
    let denied = service.login(LoginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
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

    // Now login with the approved manager succeeds.
    let login = service
        .login(LoginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
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
    let login = service
        .login(LoginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
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
async fn file_jobs_and_recovery_are_explicitly_unavailable() {
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
