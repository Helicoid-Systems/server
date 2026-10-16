//! Legacy password login must not bypass an enrolled MFA account.
//!
//! Covers enrolled MFA (with and without manager identity), pending MFA,
//! recovery state, and mounted HTTP `/v1/auth/login` denial. Also keeps the
//! loopback-development path available for accounts without an MFA requirement.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use hs_server::crypto::{totp_generate_at, unix_now};
use hs_server::models::{
    BootstrapRequest, BootstrapV2Request, FactorRecoveryBeginRequest, LoginRequest,
    MfaConfirmRequest,
};
use hs_server::{db, Service};

const PASSWORD: &str = "boundary-test-password-1";

fn service() -> Service {
    Service::new(db::open_in_memory().expect("isolated store"))
}

fn session_count(service: &Service) -> i64 {
    let conn = service.db_handle().lock().expect("store");
    conn.query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
        .expect("sessions")
}

/// Bootstrap + confirm real v2 MFA (no manager device key). Returns recovery codes.
fn enroll_mfa(service: &Service) -> Vec<String> {
    let token = service.create_bootstrap_token().expect("bootstrap token");
    let enrollment = service
        .bootstrap_v2(BootstrapV2Request {
            bootstrap_token: token,
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_key: None,
            manager_proof: None,
            manager_friendly_name: None,
        })
        .expect("MFA enrollment");
    service
        .confirm_mfa_enrollment(MfaConfirmRequest {
            mfa_enrollment_id: enrollment.mfa_enrollment_id,
            totp_code: totp_generate_at(&enrollment.totp_secret_base32, unix_now())
                .expect("real TOTP"),
            recovery_material_stored: true,
        })
        .expect("confirm MFA");
    enrollment.recovery_codes
}

/// Insert an approved manager identity fixture (loopback development only).
fn seed_approved_manager(service: &Service, account_id: &str) {
    let conn = service.db_handle().lock().expect("store");
    conn.execute(
        "INSERT INTO managers (
            id, public_identity, friendly_name, lifecycle_state,
            approved_by_account_id, approved_at, created_at, updated_at, public_key
         ) VALUES (
            'mgr-boundary', 'boundary-manager', 'Boundary manager', 'approved',
            ?1, ?2, ?2, ?2, NULL
         )",
        rusqlite::params![account_id, unix_now() as i64],
    )
    .expect("seed approved manager");
}

#[test]
fn enrolled_mfa_account_refuses_legacy_password_login() {
    let service = service();
    enroll_mfa(&service);
    let login = service.login(LoginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        manager_public_identity: None,
    });
    assert!(
        login.is_err(),
        "MFA account must refuse password-only login"
    );
    assert_eq!(session_count(&service), 0);
}

#[test]
fn enrolled_mfa_account_refuses_legacy_password_login_with_manager_identity() {
    let service = service();
    let token = service.create_bootstrap_token().expect("bootstrap token");
    let enrollment = service
        .bootstrap_v2(BootstrapV2Request {
            bootstrap_token: token,
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_key: None,
            manager_proof: None,
            manager_friendly_name: None,
        })
        .expect("MFA enrollment");
    service
        .confirm_mfa_enrollment(MfaConfirmRequest {
            mfa_enrollment_id: enrollment.mfa_enrollment_id.clone(),
            totp_code: totp_generate_at(&enrollment.totp_secret_base32, unix_now())
                .expect("real TOTP"),
            recovery_material_stored: true,
        })
        .expect("confirm MFA");
    seed_approved_manager(&service, &enrollment.account_id);

    let login = service.login(LoginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        manager_public_identity: Some("boundary-manager".into()),
    });
    assert!(
        login.is_err(),
        "MFA account must refuse password-only login even with an approved manager"
    );
    assert_eq!(session_count(&service), 0);
}

#[test]
fn pending_mfa_account_refuses_legacy_password_login() {
    let service = service();
    let token = service.create_bootstrap_token().expect("bootstrap token");
    service
        .bootstrap_v2(BootstrapV2Request {
            bootstrap_token: token,
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_key: None,
            manager_proof: None,
            manager_friendly_name: None,
        })
        .expect("pending MFA enrollment");
    let login = service.login(LoginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        manager_public_identity: None,
    });
    assert!(
        login.is_err(),
        "pending MFA must refuse password-only login"
    );
    assert_eq!(session_count(&service), 0);
}

#[test]
fn recovery_state_account_refuses_legacy_password_login() {
    let service = service();
    let recovery_codes = enroll_mfa(&service);
    let code = recovery_codes.first().expect("recovery code");
    service
        .begin_factor_recovery(FactorRecoveryBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            recovery_code: code.clone(),
        })
        .expect("recovery begin");
    let login = service.login(LoginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        manager_public_identity: None,
    });
    assert!(
        login.is_err(),
        "recovery-state account must refuse password-only login"
    );
    assert_eq!(session_count(&service), 0);
}

#[test]
fn legacy_login_remains_available_without_mfa_requirement() {
    // Loopback development login stays open for a non-administrator account
    // with no MFA requirement. (Administrator MFA is mandatory — a v1
    // bootstrap administrator cannot password-login.)
    let service = service();
    {
        let conn = service.db_handle().lock().expect("store");
        let hash = hs_server::crypto::hash_password("legacy-op-password-1").expect("hash");
        let now = unix_now() as i64;
        conn.execute(
            "INSERT INTO accounts (
                id, username, password_hash, state,
                can_operate, can_manage_enrollment, can_manage_access,
                can_manage_accounts, can_manage_security,
                revision, created_at, updated_at
             ) VALUES ('legacy-op', 'legacy-op', ?1, 'active', 1, 0, 0, 0, 0, 1, ?2, ?2)",
            rusqlite::params![hash, now],
        )
        .expect("seed legacy non-admin");
    }
    let login = service
        .login(LoginRequest {
            username: "legacy-op".into(),
            password: "legacy-op-password-1".into(),
            manager_public_identity: None,
        })
        .expect("legacy login without MFA");
    assert_eq!(session_count(&service), 1);
    // Drop the ephemeral session; this test only checks the path stays open.
    let auth = service
        .authenticate_token(&login.token)
        .expect("legacy session");
    service.logout(&auth).expect("release legacy session");
}

#[test]
fn legacy_login_refuses_administrator_without_mfa() {
    let service = service();
    let token = service.create_bootstrap_token().expect("bootstrap token");
    service
        .bootstrap(BootstrapRequest {
            bootstrap_token: token,
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_identity: None,
            manager_friendly_name: None,
        })
        .expect("v1 bootstrap");
    let denied = service.login(LoginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        manager_public_identity: None,
    });
    assert!(
        denied.is_err(),
        "mandatory administrator MFA must refuse v1 password login"
    );
    assert_eq!(session_count(&service), 0);
}

#[tokio::test]
async fn http_login_denies_enrolled_mfa_without_token_or_session() {
    let service = std::sync::Arc::new(service());
    enroll_mfa(&service);
    let app: Router = hs_server::app(service.clone());

    let request = Request::builder()
        .method("POST")
        .uri("/v1/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "username": "admin",
                "password": PASSWORD,
            })
            .to_string(),
        ))
        .expect("request");
    let response = app.oneshot(request).await.expect("oneshot");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json body")
    };

    assert_eq!(status, StatusCode::FORBIDDEN, "MFA must refuse login");
    assert!(
        body.get("token").is_none(),
        "denied login must not return a token"
    );
    assert_eq!(
        session_count(&service),
        0,
        "no session rows after HTTP denial"
    );
}
